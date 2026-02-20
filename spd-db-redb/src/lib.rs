// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spd_cve_client::decode_raw_vulns;
use spd_db::{
    CacheEntryInfo, CveRecord, DatabaseBackend, DatabaseError, DatabaseStats, Package, TtlSelector,
};

/// RedB table: key = `"name::version"`, value = JSON of `StoredEntry`.
const CACHE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("cve_cache");

/// RedB table for persisted stats: keys "hits", "misses"; values decimal strings.
const METADATA_TABLE: TableDefinition<&str, &str> = TableDefinition::new("metadata");

/// Serialized form of a cache entry (raw vuln JSON per package+provider + TTL).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEntry {
    raw_vulns: Vec<serde_json::Value>,
    provider_id: String,
    #[serde(rename = "expires_at_secs")]
    expires_at_secs: u64,
    #[serde(default)]
    added_at_secs: Option<u64>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// Minimal struct for purge: only need expires_at to decide whether to remove.
#[derive(serde::Deserialize)]
struct PurgeEntry {
    #[serde(rename = "expires_at_secs")]
    expires_at_secs: u64,
}

/// Normalize after deserialization: fill added_at_secs/ttl_secs from expiry if missing.
fn normalize_stored_entry(entry: &mut StoredEntry, default_ttl_secs: u64) {
    if entry.added_at_secs.is_none() || entry.ttl_secs.is_none() {
        let ttl = entry.ttl_secs.unwrap_or(default_ttl_secs);
        entry.added_at_secs = Some(entry.expires_at_secs.saturating_sub(ttl));
        entry.ttl_secs = Some(ttl);
    }
}

fn pkg_cache_key(pkg: &Package, provider_id: &str) -> String {
    format!("{}::{}::{}", pkg.name, pkg.version, provider_id)
}

/// Load persisted hits/misses and cache_ttl_secs from the metadata table.
/// Returns (hits, misses, optional stored TTL).
fn load_metadata(db: &Database) -> (usize, usize, Option<u64>) {
    let read_txn = match db.begin_read() {
        Ok(t) => t,
        Err(_) => return (0, 0, None),
    };
    let table = match read_txn.open_table(METADATA_TABLE) {
        Ok(t) => t,
        Err(_) => return (0, 0, None),
    };
    let hits = table
        .get("hits")
        .ok()
        .flatten()
        .and_then(|g| g.value().parse().ok())
        .unwrap_or(0);
    let misses = table
        .get("misses")
        .ok()
        .flatten()
        .and_then(|g| g.value().parse().ok())
        .unwrap_or(0);
    let cache_ttl_secs = table
        .get("cache_ttl_secs")
        .ok()
        .flatten()
        .and_then(|g| g.value().parse().ok());
    (hits, misses, cache_ttl_secs)
}

/// Persist hits, misses, and cache_ttl_secs to the metadata table (best-effort).
fn persist_stats(db: &Database, hits: usize, misses: usize, ttl_secs: u64) {
    let write_txn = match db.begin_write() {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut table = match write_txn.open_table(METADATA_TABLE) {
        Ok(t) => t,
        Err(_) => return,
    };
    let h = hits.to_string();
    let m = misses.to_string();
    let t = ttl_secs.to_string();
    let _ = table.insert("hits", h.as_str());
    let _ = table.insert("misses", m.as_str());
    let _ = table.insert("cache_ttl_secs", t.as_str());
    drop(table);
    let _ = write_txn.commit();
}

/// Inner state shared by clones; Drop persists hit/miss counts for next process.
struct RedbBackendInner {
    db: Arc<Database>,
    ttl_secs: u64,
    hits: Arc<AtomicUsize>,
    misses: Arc<AtomicUsize>,
}

fn persist_stats_on_drop(inner: &RedbBackendInner) {
    persist_stats(
        inner.db.as_ref(),
        inner.hits.load(Ordering::Relaxed),
        inner.misses.load(Ordering::Relaxed),
        inner.ttl_secs,
    );
}

impl Drop for RedbBackendInner {
    fn drop(&mut self) {
        persist_stats_on_drop(self);
    }
}

/// Real RedB backend: one file, cache table + metadata for stats.
#[derive(Clone)]
pub struct RedbBackend {
    inner: Arc<RedbBackendInner>,
}

impl RedbBackend {
    /// Create a new backend using a RedB file at `path`.
    ///
    /// * `path` – path to the `.redb` file (created if missing).
    /// * `ttl_secs` – time‑to‑live for cached CVE entries.
    pub fn with_path(path: PathBuf, ttl_secs: u64) -> Result<Self, DatabaseError> {
        let db = Database::create(path).map_err(DatabaseError::wrap)?;
        let db = Arc::new(db);
        let (hits, misses, _) = load_metadata(db.as_ref());
        let ttl = ttl_secs.max(1);
        persist_stats(db.as_ref(), hits, misses, ttl);
        let inner = RedbBackendInner {
            db,
            ttl_secs: ttl,
            hits: Arc::new(AtomicUsize::new(hits)),
            misses: Arc::new(AtomicUsize::new(misses)),
        };
        Ok(RedbBackend {
            inner: Arc::new(inner),
        })
    }

    /// Trigger the same persist logic as Drop. Test-only, for coverage.
    #[cfg(test)]
    pub fn __test_persist_stats_on_drop(&self) {
        persist_stats_on_drop(self.inner.as_ref());
    }

    /// Create a backend from an existing Database (test-only, to inject broken DBs).
    #[cfg(test)]
    pub fn with_database(db: Database, ttl_secs: u64) -> Result<Self, DatabaseError> {
        let db = Arc::new(db);
        let (hits, misses, _) = load_metadata(db.as_ref());
        let ttl = ttl_secs.max(1);
        persist_stats(db.as_ref(), hits, misses, ttl);
        let inner = RedbBackendInner {
            db,
            ttl_secs: ttl,
            hits: Arc::new(AtomicUsize::new(hits)),
            misses: Arc::new(AtomicUsize::new(misses)),
        };
        Ok(RedbBackend {
            inner: Arc::new(inner),
        })
    }

    /// Create a new backend with the default file path
    /// (`./spd-cache.redb` from the current directory).
    ///
    /// * `ttl_secs` – time‑to‑live for cached CVE entries.
    pub fn new(ttl_secs: u64) -> Self {
        let path = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("spd-cache.redb");
        Self::with_path(path, ttl_secs).expect("failed to open or create RedB database")
    }

    /// Remove all entries that have passed their TTL (best-effort in one write txn).
    fn purge_expired(&self) -> Result<(), DatabaseError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let write_txn = self
            .inner
            .db
            .begin_write()
            .map_err(DatabaseError::wrap)?;
        let mut table = write_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        let keys_to_remove: Vec<String> = table
            .iter()
            .map_err(DatabaseError::wrap)?
            .filter_map(|entry| {
                let (k, v) = entry.ok()?;
                let val_str = v.value();
                let purge_entry: PurgeEntry = serde_json::from_str(val_str).ok()?;
                if purge_entry.expires_at_secs <= now_secs {
                    Some(k.value().to_string())
                } else {
                    None
                }
            })
            .collect();
        for k in keys_to_remove {
            let _ = table.remove(k.as_str());
        }
        drop(table);
        write_txn
            .commit()
            .map_err(DatabaseError::wrap)?;
        Ok(())
    }
}

#[async_trait]
impl DatabaseBackend for RedbBackend {
    async fn init(&self) -> Result<(), DatabaseError> {
        spd_cve_client::ensure_default_decoders();
        self.purge_expired()
    }

    async fn get(
        &self,
        pkg: &Package,
        provider_id: &str,
    ) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
        spd_cve_client::ensure_default_decoders();
        let _ = self.purge_expired();
        let key = pkg_cache_key(pkg, provider_id);
        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(DatabaseError::wrap)?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        let guard = match table
            .get(key.as_str())
            .map_err(DatabaseError::wrap)?
        {
            Some(g) => g,
            None => {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                persist_stats(
                    self.inner.db.as_ref(),
                    self.inner.hits.load(Ordering::Relaxed),
                    self.inner.misses.load(Ordering::Relaxed),
                    self.inner.ttl_secs,
                );
                return Ok(None);
            }
        };
        let val_str = guard.value();
        let mut stored: StoredEntry = match serde_json::from_str(val_str) {
            Ok(s) => s,
            Err(_) => {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                persist_stats(
                    self.inner.db.as_ref(),
                    self.inner.hits.load(Ordering::Relaxed),
                    self.inner.misses.load(Ordering::Relaxed),
                    self.inner.ttl_secs,
                );
                return Ok(None); // wrong schema or corrupt; treat as cache miss
            }
        };
        normalize_stored_entry(&mut stored, self.inner.ttl_secs);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        if stored.expires_at_secs <= now_secs {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            persist_stats(
                self.inner.db.as_ref(),
                self.inner.hits.load(Ordering::Relaxed),
                self.inner.misses.load(Ordering::Relaxed),
                self.inner.ttl_secs,
            );
            return Ok(None);
        }
        let records = decode_raw_vulns(&stored.provider_id, &stored.raw_vulns);
        self.inner.hits.fetch_add(1, Ordering::Relaxed);
        persist_stats(
            self.inner.db.as_ref(),
            self.inner.hits.load(Ordering::Relaxed),
            self.inner.misses.load(Ordering::Relaxed),
            self.inner.ttl_secs,
        );
        Ok(Some(records))
    }

    async fn put(
        &self,
        pkg: &Package,
        provider_id: &str,
        raw_vulns: &[serde_json::Value],
        ttl_override: Option<u64>,
    ) -> Result<(), DatabaseError> {
        let key = pkg_cache_key(pkg, provider_id);
        let ttl = ttl_override.unwrap_or(self.inner.ttl_secs).max(1);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let expires_at_secs = now_secs.saturating_add(ttl);
        let entry = StoredEntry {
            raw_vulns: raw_vulns.to_vec(),
            provider_id: provider_id.to_string(),
            expires_at_secs,
            added_at_secs: Some(now_secs),
            ttl_secs: Some(ttl),
        };
        let value = serde_json::to_string(&entry).map_err(DatabaseError::Serde)?;
        let write_txn = self
            .inner
            .db
            .begin_write()
            .map_err(DatabaseError::wrap)?;
        let mut table = write_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        table
            .insert(key.as_str(), value.as_str())
            .map_err(DatabaseError::wrap)?;
        drop(table);
        write_txn
            .commit()
            .map_err(DatabaseError::wrap)?;
        Ok(())
    }

    async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(DatabaseError::wrap)?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        let total = table
            .len()
            .map_err(DatabaseError::wrap)? as usize;
        let hits = self.inner.hits.load(Ordering::Relaxed);
        let misses = self.inner.misses.load(Ordering::Relaxed);
        persist_stats(self.inner.db.as_ref(), hits, misses, self.inner.ttl_secs);
        Ok(DatabaseStats {
            cached_entries: total,
            hits,
            misses,
            cache_ttl_secs: Some(self.inner.ttl_secs),
        })
    }

    async fn list_entries(&self, full: bool) -> Result<Vec<CacheEntryInfo>, DatabaseError> {
        spd_cve_client::ensure_default_decoders();
        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(DatabaseError::wrap)?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        let mut out = Vec::new();
        for entry in table
            .iter()
            .map_err(DatabaseError::wrap)?
        {
            let (k, v) = entry.map_err(DatabaseError::wrap)?;
            let key = k.value().to_string();
            let val_str = v.value();
            let mut stored: StoredEntry = match serde_json::from_str(val_str) {
                Ok(s) => s,
                Err(_) => continue,
            };
            normalize_stored_entry(&mut stored, self.inner.ttl_secs);
            let added = stored.added_at_secs.unwrap_or(0);
            let ttl = stored.ttl_secs.unwrap_or(self.inner.ttl_secs);
            let records = decode_raw_vulns(&stored.provider_id, &stored.raw_vulns);
            let cve_ids: Vec<String> = records.iter().map(|r| r.id.clone()).collect();
            let raw_vulns = if full {
                Some(stored.raw_vulns.clone())
            } else {
                None
            };
            out.push(CacheEntryInfo {
                key,
                ttl_secs: ttl,
                added_at_secs: added,
                cve_count: stored.raw_vulns.len(),
                cve_ids,
                raw_vulns,
            });
        }
        Ok(out)
    }

    async fn set_ttl(&self, selector: TtlSelector, new_ttl_secs: u64) -> Result<(), DatabaseError> {
        let keys: Vec<String> = match &selector {
            TtlSelector::One(k) => vec![k.clone()],
            TtlSelector::Multiple(keys) => keys.clone(),
            TtlSelector::All => {
                let read_txn = self
                    .inner
                    .db
                    .begin_read()
                    .map_err(DatabaseError::wrap)?;
                let table = read_txn
                    .open_table(CACHE_TABLE)
                    .map_err(DatabaseError::wrap)?;
                table
                    .iter()
                    .map_err(DatabaseError::wrap)?
                    .filter_map(|e| {
                        let (k, _) = e.ok()?;
                        Some(k.value().to_string())
                    })
                    .collect()
            }
        };
        if keys.is_empty() {
            return Ok(());
        }
        let write_txn = self
            .inner
            .db
            .begin_write()
            .map_err(DatabaseError::wrap)?;
        let mut table = write_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        for key in keys {
            let val_str: String = match table
                .get(key.as_str())
                .map_err(DatabaseError::wrap)?
            {
                Some(g) => g.value().to_string(),
                None => continue,
            };
            let mut stored: StoredEntry = match serde_json::from_str(&val_str) {
                Ok(s) => s,
                Err(_) => continue,
            };
            normalize_stored_entry(&mut stored, self.inner.ttl_secs);
            let added = stored.added_at_secs.unwrap_or(0);
            let new_expires = added.saturating_add(new_ttl_secs);
            stored.expires_at_secs = new_expires;
            stored.ttl_secs = Some(new_ttl_secs);
            let new_val = serde_json::to_string(&stored).map_err(DatabaseError::Serde)?;
            table
                .insert(key.as_str(), new_val.as_str())
                .map_err(DatabaseError::wrap)?;
        }
        drop(table);
        write_txn
            .commit()
            .map_err(DatabaseError::wrap)?;
        Ok(())
    }

    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        use sha2::{Digest, Sha256};

        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(DatabaseError::wrap)?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(DatabaseError::wrap)?;
        let mut hasher = Sha256::new();
        for entry in table
            .iter()
            .map_err(DatabaseError::wrap)?
        {
            let (k, v) = entry.map_err(DatabaseError::wrap)?;
            let line = format!("{}|{}", k.value(), v.value());
            hasher.update(line.as_bytes());
        }
        let _hash = hasher.finalize();
        Ok(())
    }
}

impl Default for RedbBackend {
    fn default() -> Self {
        Self::new(5 * 24 * 60 * 60) // 5 days
    }
}

// ---------------------------------------------------------------------------
// False-positive (ignore) DB – separate RedB file per FR-015
// ---------------------------------------------------------------------------

/// RedB table for false-positive markings: key = CVE ID, value = JSON FpEntry.
const FALSE_POSITIVE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("false_positive");

/// Stored row for a CVE marked as false positive (FR-015: comment, timestamp, user/host, optional project_id).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FpEntry {
    pub comment: String,
    pub timestamp_secs: u64,
    pub user: Option<String>,
    pub host: Option<String>,
    pub project_id: Option<String>,
}

/// Separate RedB database for false-positive markings (spd-ignore.redb).
#[derive(Clone)]
pub struct RedbIgnoreDb {
    db: Arc<Database>,
}

impl RedbIgnoreDb {
    /// Open or create the ignore DB at `path`.
    pub fn with_path(path: PathBuf) -> Result<Self, DatabaseError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| DatabaseError::Io(e))?;
            }
        }
        let db = Database::create(path).map_err(DatabaseError::wrap)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Create from an existing Database (test-only, for injecting custom backends).
    #[cfg(test)]
    pub fn with_database(db: Database) -> Self {
        Self {
            db: Arc::new(db),
        }
    }

    /// Mark a CVE as false positive (FR-015).
    pub fn mark(
        &self,
        cve_id: &str,
        comment: &str,
        project_id: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let user = std::env::var("USER").ok();
        let host = std::env::var("HOSTNAME").ok();
        let entry = FpEntry {
            comment: comment.to_string(),
            timestamp_secs: now_secs,
            user,
            host,
            project_id: project_id.map(String::from),
        };
        let value = serde_json::to_string(&entry).map_err(DatabaseError::Serde)?;
        let write_txn = self
            .db
            .begin_write()
            .map_err(DatabaseError::wrap)?;
        let mut table = write_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(DatabaseError::wrap)?;
        table
            .insert(cve_id, value.as_str())
            .map_err(DatabaseError::wrap)?;
        drop(table);
        write_txn
            .commit()
            .map_err(DatabaseError::wrap)?;
        Ok(())
    }

    /// Remove a false-positive marking.
    pub fn unmark(&self, cve_id: &str) -> Result<(), DatabaseError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(DatabaseError::wrap)?;
        let mut table = write_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(DatabaseError::wrap)?;
        table
            .remove(cve_id)
            .map_err(DatabaseError::wrap)?;
        drop(table);
        write_txn
            .commit()
            .map_err(DatabaseError::wrap)?;
        Ok(())
    }

    /// Return true if the CVE is marked as false positive.
    pub fn is_marked(&self, cve_id: &str) -> Result<bool, DatabaseError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(DatabaseError::wrap)?;
        let table = read_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(DatabaseError::wrap)?;
        Ok(table
            .get(cve_id)
            .map_err(DatabaseError::wrap)?
            .is_some())
    }

    /// Return the set of all CVE IDs marked as false positive (for filtering in scan).
    pub fn marked_ids(&self) -> Result<std::collections::HashSet<String>, DatabaseError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(DatabaseError::wrap)?;
        let table = read_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(DatabaseError::wrap)?;
        let set: std::collections::HashSet<String> = table
            .iter()
            .map_err(DatabaseError::wrap)?
            .filter_map(|e| {
                let (k, _) = e.ok()?;
                Some(k.value().to_string())
            })
            .collect();
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// StorageBackend that fails read() after a number of successful reads.
    /// Used to trigger load_metadata's begin_read Err and persist_stats error paths.
    #[derive(Debug)]
    struct ReadFailingBackend {
        inner: redb::backends::InMemoryBackend,
        read_count: AtomicUsize,
        fail_after_reads: usize,
    }

    impl ReadFailingBackend {
        fn new(fail_after_reads: usize) -> Self {
            Self {
                inner: redb::backends::InMemoryBackend::new(),
                read_count: AtomicUsize::new(0),
                fail_after_reads,
            }
        }
    }

    impl redb::StorageBackend for ReadFailingBackend {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }

        fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
            let n = self.read_count.fetch_add(1, Ordering::SeqCst);
            if n >= self.fail_after_reads {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected read failure for coverage",
                ));
            }
            self.inner.read(offset, len)
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.inner.set_len(len)
        }

        fn sync_data(&self, eventual: bool) -> io::Result<()> {
            self.inner.sync_data(eventual)
        }

        fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            self.inner.write(offset, data)
        }
    }

    /// StorageBackend that fails write() and sync_data() after a number of successes.
    /// Used to trigger persist_stats error paths.
    #[derive(Debug)]
    struct WriteFailingBackend {
        inner: redb::backends::InMemoryBackend,
        write_count: AtomicUsize,
        fail_after_writes: usize,
    }

    impl WriteFailingBackend {
        fn new(fail_after_writes: usize) -> Self {
            Self {
                inner: redb::backends::InMemoryBackend::new(),
                write_count: AtomicUsize::new(0),
                fail_after_writes,
            }
        }
    }

    impl redb::StorageBackend for WriteFailingBackend {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }

        fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
            self.inner.read(offset, len)
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.inner.set_len(len)
        }

        fn sync_data(&self, eventual: bool) -> io::Result<()> {
            let n = self.write_count.load(Ordering::SeqCst);
            if n >= self.fail_after_writes {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected sync failure for coverage",
                ));
            }
            self.inner.sync_data(eventual)
        }

        fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            let n = self.write_count.fetch_add(1, Ordering::SeqCst);
            if n >= self.fail_after_writes {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected write failure for coverage",
                ));
            }
            self.inner.write(offset, data)
        }
    }

    /// Create a RedbBackend using in-memory storage (faster, no disk).
    fn in_memory_backend(ttl_secs: u64) -> RedbBackend {
        let db = redb::Builder::new()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .unwrap();
        RedbBackend::with_database(db, ttl_secs).unwrap()
    }

    fn temp_cache_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("spd_redb_test_{}.redb", name))
    }

    fn temp_ignore_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("spd_ignore_test_{}.redb", name))
    }

    /// OSV-like vuln JSON that raw_vuln_to_cve_record can convert.
    fn sample_raw_vuln() -> serde_json::Value {
        serde_json::json!({
            "id": "CVE-2023-test",
            "database_specific": { "cvss_v3_score": 7.0 },
            "summary": "Test vuln"
        })
    }

    /// In-memory backend helper works; put/get and stats succeed (no disk).
    #[tokio::test]
    async fn in_memory_backend_put_get_works() {
        let backend = in_memory_backend(3600);
        backend.init().await.unwrap();
        let pkg = Package {
            name: "mem_pkg".to_string(),
            version: "1.0".to_string(),
        };
        backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
        let got = backend.get(&pkg, "osv").await.unwrap();
        assert!(got.is_some());
        let stats = backend.stats().await.unwrap();
        assert!(stats.cached_entries >= 1);
        assert!(stats.hits >= 1);
    }

    /// is_marked for a CVE that was never marked returns Ok(false).
    #[tokio::test]
    async fn ignore_db_is_marked_returns_false_for_unmarked_cve() {
        let path = temp_ignore_path("is_marked_unmarked");
        let _ = std::fs::remove_file(&path);
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-2023-OTHER", "create table", None).unwrap();
        assert!(!db.is_marked("CVE-9999-NEVER").unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// unmark of a CVE that was never marked succeeds (no-op).
    #[tokio::test]
    async fn ignore_db_unmark_nonexistent_succeeds() {
        let path = temp_ignore_path("unmark_nonexistent");
        let _ = std::fs::remove_file(&path);
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-2023-A", "create table", None).unwrap();
        db.unmark("CVE-9999-NEVER").unwrap();
        assert!(db.is_marked("CVE-2023-A").unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// marked_ids returns multiple entries when several CVEs are marked.
    #[tokio::test]
    async fn ignore_db_marked_ids_multiple() {
        let path = temp_ignore_path("marked_ids_multi");
        let _ = std::fs::remove_file(&path);
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-2023-A", "a", None).unwrap();
        db.mark("CVE-2023-B", "b", None).unwrap();
        db.mark("CVE-2023-C", "c", None).unwrap();
        let ids = db.marked_ids().unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("CVE-2023-A"));
        assert!(ids.contains("CVE-2023-B"));
        assert!(ids.contains("CVE-2023-C"));
        let _ = std::fs::remove_file(&path);
    }

    /// put with ttl_override is stored and list_entries returns it (FR-035, OP-009).
    #[tokio::test]
    async fn put_with_ttl_override_stored_in_list_entries() {
        let path = temp_cache_path("ttl_override_list");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
        };
        let raw = vec![sample_raw_vuln()];
        backend.put(&pkg, "osv", &raw, Some(60)).await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1, "list_entries should return one entry");
        assert_eq!(entries[0].key, "foo::1.0::osv");
        assert_eq!(entries[0].ttl_secs, 60);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            entries[0].added_at_secs <= now && entries[0].added_at_secs + 2 >= now,
            "added_at_secs should be roughly now"
        );
    }

    #[tokio::test]
    async fn list_entries_returns_added_at_and_ttl() {
        let path = temp_cache_path("list_added_ttl");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "pkg".to_string(),
            version: "2.0".to_string(),
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], Some(120))
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 120);
        assert!(entries[0].added_at_secs > 0);
    }

    #[tokio::test]
    async fn set_ttl_all_updates_expiry() {
        let path = temp_cache_path("set_ttl_all");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg1 = Package {
            name: "a".to_string(),
            version: "1".to_string(),
        };
        let pkg2 = Package {
            name: "b".to_string(),
            version: "2".to_string(),
        };
        backend
            .put(&pkg1, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .put(&pkg2, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend.set_ttl(TtlSelector::All, 120).await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.ttl_secs == 120));
    }

    #[tokio::test]
    async fn set_ttl_one_entry() {
        let path = temp_cache_path("set_ttl_one");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg1 = Package {
            name: "a".to_string(),
            version: "1".to_string(),
        };
        let pkg2 = Package {
            name: "b".to_string(),
            version: "2".to_string(),
        };
        backend
            .put(&pkg1, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .put(&pkg2, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::One("a::1::osv".into()), 200)
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.key == "a::1::osv").unwrap();
        let b = entries.iter().find(|e| e.key == "b::2::osv").unwrap();
        assert_eq!(a.ttl_secs, 200);
        assert_eq!(b.ttl_secs, 3600);
    }

    #[tokio::test]
    async fn get_expired_entry_returns_none() {
        let path = temp_cache_path("expired");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "expired_pkg".to_string(),
            version: "1".to_string(),
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], Some(1))
            .await
            .unwrap();
        assert!(backend.get(&pkg, "osv").await.unwrap().is_some());
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let got = backend.get(&pkg, "osv").await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn list_entries_full_includes_raw_vulns() {
        let path = temp_cache_path("list_full");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "full_pkg".to_string(),
            version: "1.0".to_string(),
        };
        backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
        let entries = backend.list_entries(true).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        let raw = entries[0].raw_vulns.as_ref().unwrap();
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw[0].get("id").and_then(|v| v.as_str()),
            Some("CVE-2023-test")
        );
    }

    #[test]
    fn fp_entry_serde_roundtrip() {
        let e = FpEntry {
            comment: "false positive".to_string(),
            timestamp_secs: 1_700_000_000,
            user: Some("u".to_string()),
            host: Some("h".to_string()),
            project_id: Some("p".to_string()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let f: FpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(f.comment, e.comment);
        assert_eq!(f.timestamp_secs, e.timestamp_secs);
        assert_eq!(f.user, e.user);
        assert_eq!(f.host, e.host);
        assert_eq!(f.project_id, e.project_id);
    }

    /// FpEntry with all optional fields None roundtrips correctly.
    #[test]
    fn fp_entry_serde_minimal() {
        let e = FpEntry {
            comment: "minimal".to_string(),
            timestamp_secs: 1_700_000_001,
            user: None,
            host: None,
            project_id: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let f: FpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(f.comment, e.comment);
        assert_eq!(f.timestamp_secs, e.timestamp_secs);
        assert_eq!(f.user, None);
        assert_eq!(f.host, None);
        assert_eq!(f.project_id, None);
    }

    // -----------------------------------------------------------------------
    // Additional coverage: verify_integrity, set_ttl variants, default, etc.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_integrity_succeeds() {
        let path = temp_cache_path("verify");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        backend
            .put(
                &Package {
                    name: "x".to_string(),
                    version: "1".to_string(),
                },
                "osv",
                &[sample_raw_vuln()],
                None,
            )
            .await
            .unwrap();
        backend.verify_integrity().await.unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// verify_integrity on empty db (iter yields nothing).
    #[tokio::test]
    async fn verify_integrity_empty_db_succeeds() {
        let backend = in_memory_backend(3600);
        backend.init().await.unwrap();
        backend.verify_integrity().await.unwrap();
    }

    /// list_entries on empty cache returns empty vec.
    #[tokio::test]
    async fn list_entries_empty_returns_empty() {
        let backend = in_memory_backend(3600);
        backend.init().await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        assert!(entries.is_empty());
        let entries_full = backend.list_entries(true).await.unwrap();
        assert!(entries_full.is_empty());
    }

    /// get with mixed vulns: one converts, one doesn't; filter_map yields subset.
    #[tokio::test]
    async fn get_mixed_vulns_filters_non_convertible() {
        let path = temp_cache_path("mixed_vulns");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let vuln_ok = sample_raw_vuln();
        let vuln_no_id = serde_json::json!({ "summary": "no id" });
        let pkg = Package {
            name: "mixed".to_string(),
            version: "1".to_string(),
        };
        backend
            .put(&pkg, "osv", &[vuln_ok, vuln_no_id], None)
            .await
            .unwrap();
        let got = backend.get(&pkg, "osv").await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_some());
        let recs = got.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, "CVE-2023-test");
    }

    /// set_ttl TtlSelector::One for nonexistent key is no-op (continue branch).
    #[tokio::test]
    async fn set_ttl_one_nonexistent_skipped() {
        let path = temp_cache_path("set_ttl_one_nonexist");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        backend
            .put(
                &Package {
                    name: "real".to_string(),
                    version: "1".to_string(),
                },
                "osv",
                &[sample_raw_vuln()],
                None,
            )
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::One("fake::999::osv".into()), 99)
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 3600);
    }

    /// RedbIgnoreDb clone shares underlying DB.
    #[tokio::test]
    async fn ignore_db_clone_shares_db() {
        let path = temp_ignore_path("clone");
        let _ = std::fs::remove_file(&path);
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-X", "test", None).unwrap();
        let clone = db.clone();
        assert!(clone.is_marked("CVE-X").unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn set_ttl_multiple_keys() {
        let path = temp_cache_path("set_ttl_multi");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg1 = Package {
            name: "p1".to_string(),
            version: "1".to_string(),
        };
        let pkg2 = Package {
            name: "p2".to_string(),
            version: "2".to_string(),
        };
        backend
            .put(&pkg1, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .put(&pkg2, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .set_ttl(
                TtlSelector::Multiple(vec!["p1::1::osv".into(), "p2::2::osv".into()]),
                99,
            )
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.ttl_secs == 99));
    }

    /// set_ttl with TtlSelector::All on in-memory backend exercises full path.
    #[tokio::test]
    async fn set_ttl_all_in_memory() {
        let backend = in_memory_backend(3600);
        backend.init().await.unwrap();
        let pkg = Package {
            name: "mem".to_string(),
            version: "1".to_string(),
        };
        backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
        backend.set_ttl(TtlSelector::All, 120).await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 120);
    }

    #[tokio::test]
    async fn set_ttl_empty_multiple_is_no_op() {
        let path = temp_cache_path("set_ttl_empty");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        backend
            .put(
                &Package {
                    name: "foo".to_string(),
                    version: "1".to_string(),
                },
                "osv",
                &[sample_raw_vuln()],
                None,
            )
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::Multiple(vec![]), 999)
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 3600);
    }

    #[tokio::test]
    async fn set_ttl_nonexistent_key_skipped() {
        let path = temp_cache_path("set_ttl_nonexist");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        backend
            .put(
                &Package {
                    name: "real".to_string(),
                    version: "1".to_string(),
                },
                "osv",
                &[sample_raw_vuln()],
                None,
            )
            .await
            .unwrap();
        backend
            .set_ttl(
                TtlSelector::Multiple(vec!["real::1::osv".into(), "fake::999::osv".into()]),
                50,
            )
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        let real = entries.iter().find(|e| e.key == "real::1::osv").unwrap();
        assert_eq!(real.ttl_secs, 50);
    }

    #[tokio::test]
    async fn redb_backend_default_works() {
        let tmp = std::env::temp_dir().join("spd_redb_test_default");
        let _ = std::fs::create_dir_all(&tmp);
        let orig_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let _ = std::env::set_current_dir(&tmp);
        let cache_file = tmp.join("spd-cache.redb");
        let _ = std::fs::remove_file(&cache_file);
        let backend = RedbBackend::default();
        backend.init().await.unwrap();
        let stats = backend.stats().await.unwrap();
        assert!(stats.cache_ttl_secs.is_some());
        assert_eq!(stats.cache_ttl_secs.unwrap(), 5 * 24 * 60 * 60);
        let _ = std::env::set_current_dir(&orig_cwd);
        let _ = std::fs::remove_file(&cache_file);
    }

    /// RedbBackend::new uses default path from cwd; explicit coverage.
    #[tokio::test]
    async fn redb_backend_new_explicit() {
        let tmp = std::env::temp_dir().join("spd_redb_test_new");
        let _ = std::fs::create_dir_all(&tmp);
        let orig_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let _ = std::env::set_current_dir(&tmp);
        let cache_file = tmp.join("spd-cache.redb");
        let _ = std::fs::remove_file(&cache_file);
        let backend = RedbBackend::new(3600);
        backend.init().await.unwrap();
        let stats = backend.stats().await.unwrap();
        assert!(stats.cache_ttl_secs.is_some());
        assert_eq!(stats.cache_ttl_secs.unwrap(), 3600);
        let _ = std::env::set_current_dir(&orig_cwd);
        let _ = std::fs::remove_file(&cache_file);
    }

    /// RedbBackend::new uses PathBuf::from(".") when current_dir() fails.
    /// When cwd is a deleted directory, with_path fails; we catch the panic.
    #[tokio::test]
    async fn redb_backend_new_fallback_when_current_dir_fails() {
        let orig = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        std::env::set_current_dir(&path).expect("chdir");
        drop(dir);
        let result = std::panic::catch_unwind(|| RedbBackend::new(3600));
        std::env::set_current_dir(&orig).expect("restore cwd");
        assert!(
            result.is_err(),
            "new() should panic when cwd is deleted and fallback path fails"
        );
    }

    #[tokio::test]
    async fn ttl_zero_clamped_to_one() {
        let path = temp_cache_path("ttl_zero");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 0).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "z".to_string(),
            version: "1".to_string(),
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], Some(0))
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].ttl_secs >= 1);
    }

    #[tokio::test]
    async fn ignore_db_with_path_creates_parent_dir() {
        let parent = std::env::temp_dir().join("spd_redb_test_nested_subdir");
        let _ = std::fs::remove_dir_all(&parent);
        let path = parent.join("ignore.redb");
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-2024-X", "test", None).unwrap();
        assert!(db.is_marked("CVE-2024-X").unwrap());
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[tokio::test]
    async fn get_corrupt_json_treats_as_miss() {
        let path = temp_cache_path("corrupt_json");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            let pkg = Package {
                name: "corrupt".to_string(),
                version: "1".to_string(),
            };
            backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
        }
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut table = write_txn.open_table(CACHE_TABLE).unwrap();
                table.insert("corrupt::1::osv", "not valid json").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "corrupt".to_string(),
            version: "1".to_string(),
        };
        let got = backend.get(&pkg, "osv").await.unwrap();
        let stats = backend.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_none());
        assert_eq!(stats.misses, 1);
    }

    /// Entry without added_at_secs/ttl_secs; normalize_stored_entry fills them.
    #[tokio::test]
    async fn get_old_format_entry_normalizes() {
        let path = temp_cache_path("old_format");
        let _ = std::fs::remove_file(&path);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = now + 3600;
        let old_entry = serde_json::json!({
            "raw_vulns": [sample_raw_vuln()],
            "provider_id": "osv",
            "expires_at_secs": expires
        });
        let val = old_entry.to_string();
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache.insert("old::1::osv", val.as_str()).unwrap();
                meta.insert("hits", "0").unwrap();
                meta.insert("misses", "0").unwrap();
                meta.insert("cache_ttl_secs", "3600").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "old".to_string(),
            version: "1".to_string(),
        };
        let got = backend.get(&pkg, "osv").await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_some());
        assert_eq!(got.unwrap()[0].id, "CVE-2023-test");
    }

    #[tokio::test]
    async fn list_entries_skips_corrupt_entry() {
        let path = temp_cache_path("list_corrupt");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            backend
                .put(
                    &Package {
                        name: "good".to_string(),
                        version: "1".to_string(),
                    },
                    "osv",
                    &[sample_raw_vuln()],
                    None,
                )
                .await
                .unwrap();
        }
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut table = write_txn.open_table(CACHE_TABLE).unwrap();
                table.insert("bad::1::osv", "{{{ invalid }").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "good::1::osv");
    }

    /// list_entries(full: true) with mixed valid+corrupt: returns valid with raw_vulns,
    /// skips corrupt via continue.
    #[tokio::test]
    async fn list_entries_full_skips_corrupt_includes_raw_for_valid() {
        let path = temp_cache_path("list_full_corrupt");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            backend
                .put(
                    &Package {
                        name: "valid".to_string(),
                        version: "1".to_string(),
                    },
                    "osv",
                    &[sample_raw_vuln()],
                    None,
                )
                .await
                .unwrap();
        }
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut table = write_txn.open_table(CACHE_TABLE).unwrap();
                table.insert("corrupt::x::osv", "not json {{{").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let entries = backend.list_entries(true).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "valid::1::osv");
        let raw = entries[0].raw_vulns.as_ref().unwrap();
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw[0].get("id").and_then(|v| v.as_str()),
            Some("CVE-2023-test")
        );
    }

    #[tokio::test]
    async fn set_ttl_skips_corrupt_entry() {
        let path = temp_cache_path("set_ttl_corrupt");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            backend
                .put(
                    &Package {
                        name: "valid".to_string(),
                        version: "1".to_string(),
                    },
                    "osv",
                    &[sample_raw_vuln()],
                    None,
                )
                .await
                .unwrap();
        }
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut table = write_txn.open_table(CACHE_TABLE).unwrap();
                table.insert("corrupt::x::osv", "not json").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        backend.set_ttl(TtlSelector::All, 100).await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        let valid = entries.iter().find(|e| e.key == "valid::1::osv").unwrap();
        assert_eq!(valid.ttl_secs, 100);
    }

    #[tokio::test]
    async fn purge_expired_skips_corrupt_entry() {
        let path = temp_cache_path("purge_corrupt");
        let _ = std::fs::remove_file(&path);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired = now.saturating_sub(10);
        let expired_entry = serde_json::json!({
            "raw_vulns": [sample_raw_vuln()],
            "provider_id": "osv",
            "expires_at_secs": expired,
            "added_at_secs": expired - 3600,
            "ttl_secs": 3600
        });
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert("expired::1::osv", expired_entry.to_string().as_str())
                    .unwrap();
                cache.insert("corrupt::1::osv", "garbage").unwrap();
                meta.insert("hits", "0").unwrap();
                meta.insert("misses", "0").unwrap();
                meta.insert("cache_ttl_secs", "3600").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            entries.is_empty(),
            "expired and corrupt entries should be gone or skipped"
        );
    }

    /// purge_expired removes only expired entries; non-expired are kept.
    #[tokio::test]
    async fn purge_expired_removes_expired_keeps_valid() {
        let path = temp_cache_path("purge_mixed");
        let _ = std::fs::remove_file(&path);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired_secs = now.saturating_sub(10);
        let valid_secs = now + 3600;
        let expired_entry = serde_json::json!({
            "raw_vulns": [sample_raw_vuln()],
            "provider_id": "osv",
            "expires_at_secs": expired_secs,
            "added_at_secs": expired_secs - 3600,
            "ttl_secs": 3600
        });
        let valid_entry = serde_json::json!({
            "raw_vulns": [sample_raw_vuln()],
            "provider_id": "osv",
            "expires_at_secs": valid_secs,
            "added_at_secs": now,
            "ttl_secs": 3600
        });
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert("expired::1::osv", expired_entry.to_string().as_str())
                    .unwrap();
                cache
                    .insert("valid::1::osv", valid_entry.to_string().as_str())
                    .unwrap();
                meta.insert("hits", "0").unwrap();
                meta.insert("misses", "0").unwrap();
                meta.insert("cache_ttl_secs", "3600").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "valid::1::osv");
    }

    #[tokio::test]
    async fn ignore_db_marked_ids_empty() {
        let path = temp_ignore_path("marked_ids_empty");
        let _ = std::fs::remove_file(&path);
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("dummy", "create table", None).unwrap();
        db.unmark("dummy").unwrap();
        let ids = db.marked_ids().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn with_path_fails_on_directory() {
        let path = std::env::temp_dir();
        let result = RedbBackend::with_path(path, 3600);
        assert!(result.is_err());
    }

    /// with_path fails when parent directory does not exist.
    #[tokio::test]
    async fn with_path_fails_when_parent_missing() {
        let path = std::env::temp_dir()
            .join("spd_redb_nonexistent_parent_xxxx")
            .join("cache.redb");
        let result = RedbBackend::with_path(path, 3600);
        assert!(result.is_err());
    }

    /// RedbIgnoreDb::with_path fails when parent exists as a file.
    #[tokio::test]
    async fn ignore_db_with_path_fails_when_parent_is_file() {
        let parent = std::env::temp_dir().join("spd_redb_test_parent_file");
        let _ = std::fs::remove_file(&parent);
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::write(&parent, "not a directory").unwrap();
        let path = parent.join("ignore.redb");
        let result = RedbIgnoreDb::with_path(path);
        let _ = std::fs::remove_file(&parent);
        assert!(result.is_err());
    }

    /// RedbBackendInner Drop calls persist_stats on teardown.
    #[tokio::test]
    async fn backend_drop_persists_stats() {
        let path = temp_cache_path("drop_persist");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "d".to_string(),
            version: "1".to_string(),
        };
        backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
        let _ = backend.get(&pkg, "osv").await.unwrap();
        let stats_before = backend.stats().await.unwrap();
        assert!(stats_before.hits >= 1);
        std::mem::drop(backend);
        let backend2 = RedbBackend::with_path(path.clone(), 3600).unwrap();
        let stats_after = backend2.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            stats_after.hits >= 1,
            "Drop should have persisted stats for next instance"
        );
    }

    /// persist_stats_on_drop logic (same as RedbBackendInner::drop) exercised explicitly.
    #[tokio::test]
    async fn persist_stats_on_drop_explicit_call() {
        let path = temp_cache_path("persist_on_drop");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            let pkg = Package {
                name: "p".to_string(),
                version: "1".to_string(),
            };
            backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
            let _ = backend.get(&pkg, "osv").await.unwrap();
            backend.__test_persist_stats_on_drop();
        }
        let backend2 = RedbBackend::with_path(path.clone(), 3600).unwrap();
        let stats = backend2.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(stats.hits >= 1);
    }

    /// load_metadata with valid metadata: hits, misses, cache_ttl_secs all parse.
    #[tokio::test]
    async fn load_metadata_valid_parse_uses_persisted_values() {
        let path = temp_cache_path("valid_meta");
        let _ = std::fs::remove_file(&path);
        let db = redb::Database::create(&path).unwrap();
        {
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert(
                        "dummy::1",
                        r#"{"raw_vulns":[],"expires_at_secs":9999999999}"#,
                    )
                    .unwrap();
                meta.insert("hits", "5").unwrap();
                meta.insert("misses", "3").unwrap();
                meta.insert("cache_ttl_secs", "7200").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_database(db, 3600).unwrap();
        let stats = backend.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(stats.hits, 5);
        assert_eq!(stats.misses, 3);
    }

    /// load_metadata parse-failure: invalid hits/misses/cache_ttl_secs values
    /// default to 0/None; backend initializes correctly.
    #[tokio::test]
    async fn load_metadata_invalid_parse_returns_defaults() {
        let path = temp_cache_path("invalid_parse");
        let _ = std::fs::remove_file(&path);
        let db = redb::Database::create(&path).unwrap();
        {
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert(
                        "dummy::1",
                        r#"{"raw_vulns":[],"expires_at_secs":9999999999}"#,
                    )
                    .unwrap();
                meta.insert("hits", "not_a_number").unwrap();
                meta.insert("misses", "bad").unwrap();
                meta.insert("cache_ttl_secs", "invalid").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_database(db, 3600).unwrap();
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.hits, 0, "parse failure should default hits to 0");
        assert_eq!(stats.misses, 0, "parse failure should default misses to 0");
        let _ = std::fs::remove_file(&path);
    }

    /// load_metadata with METADATA_TABLE empty (no keys) returns (0, 0, None).
    #[tokio::test]
    async fn load_metadata_empty_table_returns_defaults() {
        let path = temp_cache_path("empty_meta");
        let _ = std::fs::remove_file(&path);
        let db = redb::Database::create(&path).unwrap();
        {
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert(
                        "dummy::1",
                        r#"{"raw_vulns":[],"expires_at_secs":9999999999}"#,
                    )
                    .unwrap();
                drop(meta);
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_database(db, 3600).unwrap();
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        let _ = std::fs::remove_file(&path);
    }

    /// list_entries: raw_vulns where some lack "id" produce fewer cve_ids.
    #[tokio::test]
    async fn list_entries_vuln_without_id_omitted_from_cve_ids() {
        let path = temp_cache_path("list_no_id");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let vuln_with_id = sample_raw_vuln();
        let vuln_without_id = serde_json::json!({"summary": "no id field"});
        let pkg = Package {
            name: "mixed".to_string(),
            version: "1".to_string(),
        };
        backend
            .put(&pkg, "osv", &[vuln_with_id, vuln_without_id], None)
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_count, 2);
        assert_eq!(entries[0].cve_ids, vec!["CVE-2023-test"]);
    }

    /// list_entries: vuln with "id" as non-string (e.g. number) omitted from cve_ids.
    #[tokio::test]
    async fn list_entries_vuln_id_non_string_omitted() {
        let path = temp_cache_path("list_id_non_str");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let vuln_ok = sample_raw_vuln();
        let vuln_id_number = serde_json::json!({"id": 12345, "summary": "id is number"});
        let pkg = Package {
            name: "mixed_id".to_string(),
            version: "1".to_string(),
        };
        backend
            .put(&pkg, "osv", &[vuln_ok, vuln_id_number], None)
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_ids, vec!["CVE-2023-test"]);
    }

    /// get with raw_vulns that all fail raw_vuln_to_cve_record returns Some(vec![]).
    #[tokio::test]
    async fn get_all_vulns_non_convertible_returns_empty_records() {
        let path = temp_cache_path("all_non_conv");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let vulns_no_id: Vec<serde_json::Value> = vec![
            serde_json::json!({"summary": "a"}),
            serde_json::json!({"summary": "b"}),
        ];
        let pkg = Package {
            name: "no_conv".to_string(),
            version: "1".to_string(),
        };
        backend.put(&pkg, "osv", &vulns_no_id, None).await.unwrap();
        let got = backend.get(&pkg, "osv").await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_some());
        assert!(got.unwrap().is_empty());
    }

    /// normalize_stored_entry: entry with ttl_secs but no added_at_secs fills added.
    #[tokio::test]
    async fn list_entries_entry_missing_added_uses_ttl() {
        let path = temp_cache_path("list_no_added");
        let _ = std::fs::remove_file(&path);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = now + 3600;
        let ttl = 120u64;
        let partial = serde_json::json!({
            "raw_vulns": [sample_raw_vuln()],
            "provider_id": "osv",
            "expires_at_secs": expires,
            "ttl_secs": ttl
        });
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert("partial::1::osv", partial.to_string().as_str())
                    .unwrap();
                meta.insert("hits", "0").unwrap();
                meta.insert("misses", "0").unwrap();
                meta.insert("cache_ttl_secs", "3600").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 120);
        assert_eq!(entries[0].added_at_secs, expires.saturating_sub(120));
    }

    /// normalize_stored_entry: entry with added_at_secs but no ttl_secs fills from default.
    #[tokio::test]
    async fn list_entries_entry_missing_ttl_uses_default() {
        let path = temp_cache_path("list_no_ttl");
        let _ = std::fs::remove_file(&path);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let added = now.saturating_sub(60);
        let expires = now + 3600;
        let partial = serde_json::json!({
            "raw_vulns": [sample_raw_vuln()],
            "provider_id": "osv",
            "expires_at_secs": expires,
            "added_at_secs": added
        });
        {
            let db = redb::Database::create(&path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                let mut meta = write_txn.open_table(METADATA_TABLE).unwrap();
                cache
                    .insert("partial::1::osv", partial.to_string().as_str())
                    .unwrap();
                meta.insert("hits", "0").unwrap();
                meta.insert("misses", "0").unwrap();
                meta.insert("cache_ttl_secs", "3600").unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 3600);
    }

    /// RedbBackend clone shares underlying DB; both see same data.
    #[tokio::test]
    async fn redb_backend_clone_shares_db() {
        let backend = in_memory_backend(3600);
        backend.init().await.unwrap();
        let pkg = Package {
            name: "shared".to_string(),
            version: "1".to_string(),
        };
        backend.put(&pkg, "osv", &[sample_raw_vuln()], None).await.unwrap();
        let clone = backend.clone();
        let got = clone.get(&pkg, "osv").await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap()[0].id, "CVE-2023-test");
    }

    /// get with empty raw_vulns returns Some(vec![]).
    #[tokio::test]
    async fn get_empty_raw_vulns_returns_empty_vec() {
        let path = temp_cache_path("empty_vulns");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "empty".to_string(),
            version: "1".to_string(),
        };
        backend.put(&pkg, "osv", &[], None).await.unwrap();
        let got = backend.get(&pkg, "osv").await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_some());
        assert!(got.unwrap().is_empty());
    }

    /// load_metadata and persist_stats error paths: DB with no METADATA_TABLE.
    #[tokio::test]
    async fn load_metadata_and_persist_stats_fail_gracefully_without_metadata_table() {
        let path = temp_cache_path("no_meta_table");
        let _ = std::fs::remove_file(&path);
        let db = redb::Database::create(&path).unwrap();
        {
            let write_txn = db.begin_write().unwrap();
            {
                let mut cache = write_txn.open_table(CACHE_TABLE).unwrap();
                cache
                    .insert(
                        "x::1",
                        r#"{"raw_vulns":[{"id":"CVE-X","summary":"x"}],"expires_at_secs":9999999999}"#,
                    )
                    .unwrap();
            }
            write_txn.commit().unwrap();
        }
        let backend = RedbBackend::with_database(db, 3600).unwrap();
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        let pkg = Package {
            name: "nonexist".to_string(),
            version: "0".to_string(),
        };
        let got = backend.get(&pkg, "osv").await.unwrap();
        assert!(got.is_none());
        drop(backend);
        let _ = std::fs::remove_file(&path);
    }

    /// load_metadata returns (0,0,None) when db.begin_read() fails (custom backend).
    /// ReadFailingBackend fails after N reads; creation uses some reads, so we pick
    /// N so the first read in load_metadata fails.
    #[tokio::test]
    async fn load_metadata_begin_read_fails_returns_defaults() {
        let backend = ReadFailingBackend::new(10);
        let db = redb::Builder::new()
            .create_with_backend(backend)
            .expect("create should succeed");
        let _b = RedbBackend::with_database(db, 3600)
            .expect("with_database succeeds when load_metadata returns (0,0,None)");
    }

    /// persist_stats returns early when db.begin_write() or write fails (custom backend).
    #[tokio::test]
    async fn persist_stats_begin_write_fails_gracefully() {
        let backend = ReadFailingBackend::new(1000);
        let db = redb::Builder::new().create_with_backend(backend).unwrap();
        let _b = RedbBackend::with_database(db, 3600).unwrap();
    }

    /// persist_stats fails when write/sync fails during commit (WriteFailingBackend).
    #[tokio::test]
    async fn persist_stats_write_fails_gracefully() {
        let backend = WriteFailingBackend::new(20);
        let db = redb::Builder::new()
            .create_with_backend(backend)
            .expect("create should succeed");
        let _b = RedbBackend::with_database(db, 3600)
            .expect("with_database succeeds; persist_stats best-effort");
    }

    /// list_entries propagates error when table iteration yields Err (ReadFailingBackend).
    /// Fail threshold tuned so we succeed through init+put but fail during iteration.
    #[tokio::test]
    async fn list_entries_iteration_read_fails_propagates() {
        for fail_after in [5, 6, 7, 8, 9, 10, 11, 12] {
            let backend = ReadFailingBackend::new(fail_after);
            let db = redb::Builder::new()
                .create_with_backend(backend)
                .expect("create should succeed");
            let Ok(b) = RedbBackend::with_database(db, 3600) else {
                continue;
            };
            if b.init().await.is_err() {
                continue;
            }
            let pkg = Package {
                name: "pkg".to_string(),
                version: "1".to_string(),
            };
            if b.put(&pkg, "osv", &[sample_raw_vuln()], None).await.is_err() {
                continue;
            }
            let res = b.list_entries(false).await;
            if res.is_err() {
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains("injected read failure") || err_msg.contains("read"),
                    "fail_after={} error should mention read: {}",
                    fail_after,
                    err_msg
                );
                return;
            }
        }
        panic!("list_entries should fail for some fail_after threshold");
    }

    /// verify_integrity propagates error when table iteration yields Err.
    #[tokio::test]
    async fn verify_integrity_iteration_read_fails_propagates() {
        for fail_after in [5, 6, 7, 8, 9, 10, 11, 12, 15, 18, 20] {
            let backend = ReadFailingBackend::new(fail_after);
            let db = redb::Builder::new()
                .create_with_backend(backend)
                .expect("create should succeed");
            let Ok(b) = RedbBackend::with_database(db, 3600) else {
                continue;
            };
            if b.init().await.is_err() {
                continue;
            }
            let pkg = Package {
                name: "pkg".to_string(),
                version: "1".to_string(),
            };
            if b.put(&pkg, "osv", &[sample_raw_vuln()], None).await.is_err() {
                continue;
            }
            let res = b.verify_integrity().await;
            if res.is_err() {
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains("injected read failure") || err_msg.contains("read"),
                    "fail_after={} error should mention read: {}",
                    fail_after,
                    err_msg
                );
                return;
            }
        }
        panic!("verify_integrity should fail for some fail_after threshold");
    }

    /// purge_expired (via init) when iteration read fails: iter().map_err propagates.
    #[tokio::test]
    async fn purge_expired_iteration_read_fails_graceful() {
        let backend = ReadFailingBackend::new(15);
        let db = redb::Builder::new()
            .create_with_backend(backend)
            .expect("create should succeed");
        let b = RedbBackend::with_database(db, 3600).unwrap();
        b.init().await.unwrap();
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1".to_string(),
        };
        b.put(&pkg, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let res = b.init().await;
        if let Err(e) = res {
            assert!(
                e.to_string().contains("injected read failure")
                    || e.to_string().contains("read"),
                "unexpected error: {}",
                e
            );
        }
    }

    /// set_ttl with TtlSelector::All propagates error when iteration read fails.
    #[tokio::test]
    async fn set_ttl_all_iteration_read_fails_propagates() {
        for fail_after in [5, 6, 7, 8, 9, 10, 11, 12, 15, 18, 20] {
            let backend = ReadFailingBackend::new(fail_after);
            let db = redb::Builder::new()
                .create_with_backend(backend)
                .expect("create should succeed");
            let Ok(b) = RedbBackend::with_database(db, 3600) else {
                continue;
            };
            if b.init().await.is_err() {
                continue;
            }
            let pkg = Package {
                name: "pkg".to_string(),
                version: "1".to_string(),
            };
            if b.put(&pkg, "osv", &[sample_raw_vuln()], None).await.is_err() {
                continue;
            }
            let res = b.set_ttl(TtlSelector::All, 120).await;
            if res.is_err() {
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains("injected read failure") || err_msg.contains("read"),
                    "fail_after={} error should mention read: {}",
                    fail_after,
                    err_msg
                );
                return;
            }
        }
        panic!("set_ttl All should fail for some fail_after threshold");
    }

    /// marked_ids filter_map Err branch: iteration yields Err, e.ok()? skips.
    #[tokio::test]
    async fn marked_ids_iteration_read_fails_graceful() {
        for fail_after in [5, 6, 7, 8, 9, 10, 11, 12, 15, 18, 20] {
            let backend = ReadFailingBackend::new(fail_after);
            let db = redb::Builder::new()
                .create_with_backend(backend)
                .expect("create should succeed");
            let ignore_db = RedbIgnoreDb::with_database(db);
            ignore_db.mark("CVE-2023-X", "test", None).unwrap();
            let res = ignore_db.marked_ids();
            if res.is_err() {
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains("injected read failure") || err_msg.contains("read"),
                    "fail_after={} error should mention read: {}",
                    fail_after,
                    err_msg
                );
                return;
            }
        }
    }
}
