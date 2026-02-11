// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

#![deny(unsafe_code)]

use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spd_cve_client::raw_vuln_to_cve_record;
use spd_db::{
    CacheEntryInfo, CveRecord, DatabaseBackend, DatabaseError, DatabaseStats, Package,
    TtlSelector,
};

/// RedB table: key = `"name::version"`, value = JSON of `StoredEntry`.
const CACHE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("cve_cache");

/// RedB table for persisted stats: keys "hits", "misses"; values decimal strings.
const METADATA_TABLE: TableDefinition<&str, &str> = TableDefinition::new("metadata");

/// Serialized form of a cache entry (raw OSV vuln JSON per package + TTL).
/// Old entries may lack added_at_secs/ttl_secs; they are inferred when missing.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEntry {
    raw_vulns: Vec<serde_json::Value>,
    #[serde(rename = "expires_at_secs")]
    expires_at_secs: u64,
    #[serde(default)]
    added_at_secs: Option<u64>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// Normalize after deserialization: fill added_at_secs/ttl_secs from expiry if missing.
fn normalize_stored_entry(entry: &mut StoredEntry, default_ttl_secs: u64) {
    if entry.added_at_secs.is_none() || entry.ttl_secs.is_none() {
        let ttl = entry.ttl_secs.unwrap_or(default_ttl_secs);
        entry.added_at_secs = Some(
            entry.expires_at_secs.saturating_sub(ttl),
        );
        entry.ttl_secs = Some(ttl);
    }
}

fn pkg_key(pkg: &Package) -> String {
    format!("{}::{}", pkg.name, pkg.version)
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

impl Drop for RedbBackendInner {
    fn drop(&mut self) {
        persist_stats(
            &self.db,
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.ttl_secs,
        );
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
        let db = Database::create(path).map_err(|e| DatabaseError::Other(e.to_string()))?;
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
        Self::with_path(path, ttl_secs)
            .expect("failed to open or create RedB database")
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
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut table = write_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let keys_to_remove: Vec<String> = table
            .iter()
            .map_err(|e| DatabaseError::Other(e.to_string()))?
            .filter_map(|entry| {
                let (k, v) = entry.ok()?;
                let val_str = v.value();
                let stored: StoredEntry = serde_json::from_str(val_str).ok()?;
                if stored.expires_at_secs <= now_secs {
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
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl DatabaseBackend for RedbBackend {
    async fn init(&self) -> Result<(), DatabaseError> {
        self.purge_expired()
    }

    async fn get(&self, pkg: &Package) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
        let _ = self.purge_expired();
        let key = pkg_key(pkg);
        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let guard = match table
            .get(key.as_str())
            .map_err(|e| DatabaseError::Other(e.to_string()))?
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
        let records: Vec<CveRecord> = stored
            .raw_vulns
            .iter()
            .filter_map(raw_vuln_to_cve_record)
            .collect();
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
        raw_vulns: &[serde_json::Value],
        ttl_override: Option<u64>,
    ) -> Result<(), DatabaseError> {
        let key = pkg_key(pkg);
        let ttl = ttl_override.unwrap_or(self.inner.ttl_secs).max(1);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let expires_at_secs = now_secs.saturating_add(ttl);
        let entry = StoredEntry {
            raw_vulns: raw_vulns.to_vec(),
            expires_at_secs,
            added_at_secs: Some(now_secs),
            ttl_secs: Some(ttl),
        };
        let value = serde_json::to_string(&entry).map_err(DatabaseError::Serde)?;
        let write_txn = self
            .inner
            .db
            .begin_write()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut table = write_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        table
            .insert(key.as_str(), value.as_str())
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        drop(table);
        write_txn
            .commit()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(())
    }

    async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let total = table
            .len()
            .map_err(|e| DatabaseError::Other(e.to_string()))? as usize;
        let hits = self.inner.hits.load(Ordering::Relaxed);
        let misses = self.inner.misses.load(Ordering::Relaxed);
        persist_stats(
            self.inner.db.as_ref(),
            hits,
            misses,
            self.inner.ttl_secs,
        );
        Ok(DatabaseStats {
            cached_entries: total,
            hits,
            misses,
            cache_ttl_secs: Some(self.inner.ttl_secs),
        })
    }

    async fn list_entries(&self, full: bool) -> Result<Vec<CacheEntryInfo>, DatabaseError> {
        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut out = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| DatabaseError::Other(e.to_string()))?
        {
            let (k, v) = entry.map_err(|e| DatabaseError::Other(e.to_string()))?;
            let key = k.value().to_string();
            let val_str = v.value();
            let mut stored: StoredEntry = match serde_json::from_str(val_str) {
                Ok(s) => s,
                Err(_) => continue,
            };
            normalize_stored_entry(&mut stored, self.inner.ttl_secs);
            let added = stored.added_at_secs.unwrap_or(0);
            let ttl = stored.ttl_secs.unwrap_or(self.inner.ttl_secs);
            let cve_ids: Vec<String> = stored
                .raw_vulns
                .iter()
                .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
                .map(String::from)
                .collect();
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

    async fn set_ttl(
        &self,
        selector: TtlSelector,
        new_ttl_secs: u64,
    ) -> Result<(), DatabaseError> {
        let keys: Vec<String> = match &selector {
            TtlSelector::One(k) => vec![k.clone()],
            TtlSelector::Multiple(keys) => keys.clone(),
            TtlSelector::All => {
                let read_txn = self
                    .inner
                    .db
                    .begin_read()
                    .map_err(|e| DatabaseError::Other(e.to_string()))?;
                let table = read_txn
                    .open_table(CACHE_TABLE)
                    .map_err(|e| DatabaseError::Other(e.to_string()))?;
                table
                    .iter()
                    .map_err(|e| DatabaseError::Other(e.to_string()))?
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
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut table = write_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        for key in keys {
            let val_str: String = match table.get(key.as_str()).map_err(|e| DatabaseError::Other(e.to_string()))? {
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
                .map_err(|e| DatabaseError::Other(e.to_string()))?;
        }
        drop(table);
        write_txn
            .commit()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(())
    }

    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        use sha2::{Digest, Sha256};

        let read_txn = self
            .inner
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut hasher = Sha256::new();
        for entry in table
            .iter()
            .map_err(|e| DatabaseError::Other(e.to_string()))?
        {
            let (k, v) = entry.map_err(|e| DatabaseError::Other(e.to_string()))?;
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
        let db = Database::create(path).map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(Self { db: Arc::new(db) })
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
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut table = write_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        table
            .insert(cve_id, value.as_str())
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        drop(table);
        write_txn
            .commit()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(())
    }

    /// Remove a false-positive marking.
    pub fn unmark(&self, cve_id: &str) -> Result<(), DatabaseError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut table = write_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        table
            .remove(cve_id)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        drop(table);
        write_txn
            .commit()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(())
    }

    /// Return true if the CVE is marked as false positive.
    pub fn is_marked(&self, cve_id: &str) -> Result<bool, DatabaseError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(table
            .get(cve_id)
            .map_err(|e| DatabaseError::Other(e.to_string()))?
            .is_some())
    }

    /// Return the set of all CVE IDs marked as false positive (for filtering in scan).
    pub fn marked_ids(&self) -> Result<std::collections::HashSet<String>, DatabaseError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(FALSE_POSITIVE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let set: std::collections::HashSet<String> = table
            .iter()
            .map_err(|e| DatabaseError::Other(e.to_string()))?
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

    #[tokio::test]
    async fn redb_backend_init_succeeds() {
        let path = temp_cache_path("init");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn redb_backend_put_then_get() {
        let path = temp_cache_path("put_get");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
        };
        let raw = vec![sample_raw_vuln()];
        backend.put(&pkg, &raw, None).await.unwrap();
        let got = backend.get(&pkg).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(got.is_some());
        let recs = got.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, "CVE-2023-test");
        assert_eq!(recs[0].cvss_score, Some(7.0));
    }

    #[tokio::test]
    async fn redb_backend_get_unknown_returns_none_increments_misses() {
        let path = temp_cache_path("misses");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "nonexistent".to_string(),
            version: "0".to_string(),
        };
        let r1 = backend.get(&pkg).await.unwrap();
        let r2 = backend.get(&pkg).await.unwrap();
        let stats = backend.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(r1.is_none());
        assert!(r2.is_none());
        assert_eq!(stats.misses, 2);
    }

    #[tokio::test]
    async fn redb_backend_stats() {
        let path = temp_cache_path("stats");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "p".to_string(),
            version: "1".to_string(),
        };
        backend.put(&pkg, &[sample_raw_vuln()], None).await.unwrap();
        let _ = backend.get(&pkg).await.unwrap();
        let stats = backend.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(stats.cached_entries >= 1);
        assert!(stats.hits >= 1);
    }

    /// Stats must show non-zero hits after a cache hit in the same process.
    #[tokio::test]
    async fn stats_reflect_hits_after_get() {
        let path = temp_cache_path("stats_hits");
        let _ = std::fs::remove_file(&path);
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
        };
        backend.put(&pkg, &[sample_raw_vuln()], None).await.unwrap();
        let _ = backend.get(&pkg).await.unwrap();
        let _ = backend.get(&pkg).await.unwrap();
        let stats = backend.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(stats.hits, 2, "stats should show 2 hits after two get(hit)");
        assert_eq!(stats.misses, 0);
    }

    /// Stats must persist across backend instances (e.g. spd scan then spd db stats).
    #[tokio::test]
    async fn stats_persisted_across_backend_instances() {
        let path = temp_cache_path("stats_persist");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            let pkg = Package {
                name: "foo".to_string(),
                version: "2.0".to_string(),
            };
            backend.put(&pkg, &[sample_raw_vuln()], None).await.unwrap();
            let _ = backend.get(&pkg).await.unwrap();
        }
        let backend2 = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend2.init().await.unwrap();
        let stats = backend2.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            stats.hits >= 1,
            "new backend must see persisted hits (got {})",
            stats.hits
        );
        assert!(stats.cached_entries >= 1);
    }

    /// Miss counts must persist across backend instances (persist on get(miss)).
    #[tokio::test]
    async fn stats_persisted_misses_across_backend_instances() {
        let path = temp_cache_path("stats_misses_persist");
        let _ = std::fs::remove_file(&path);
        {
            let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
            backend.init().await.unwrap();
            let pkg = Package {
                name: "nonexistent".to_string(),
                version: "0".to_string(),
            };
            let _ = backend.get(&pkg).await.unwrap();
            let _ = backend.get(&pkg).await.unwrap();
        }
        let backend2 = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend2.init().await.unwrap();
        let stats = backend2.stats().await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            stats.misses, 2,
            "new backend must see persisted misses (got {})",
            stats.misses
        );
    }

    #[tokio::test]
    async fn redb_ignore_db_mark_unmark_fr015() {
        let path = temp_ignore_path("mark_unmark");
        let _ = std::fs::remove_file(&path);
        let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-2023-1234", "vendor bug", Some("proj1"))
            .unwrap();
        assert!(db.is_marked("CVE-2023-1234").unwrap());
        let ids = db.marked_ids().unwrap();
        assert!(ids.contains("CVE-2023-1234"));
        db.unmark("CVE-2023-1234").unwrap();
        assert!(!db.is_marked("CVE-2023-1234").unwrap());
        assert!(db.marked_ids().unwrap().is_empty());
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
        backend.put(&pkg, &raw, Some(60)).await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1, "list_entries should return one entry");
        assert_eq!(entries[0].key, "foo::1.0");
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
            .put(&pkg, &[sample_raw_vuln()], Some(120))
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
            .put(&pkg1, &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .put(&pkg2, &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::All, 120)
            .await
            .unwrap();
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
            .put(&pkg1, &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .put(&pkg2, &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::One("a::1".into()), 200)
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.key == "a::1").unwrap();
        let b = entries.iter().find(|e| e.key == "b::2").unwrap();
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
            .put(&pkg, &[sample_raw_vuln()], Some(1))
            .await
            .unwrap();
        assert!(backend.get(&pkg).await.unwrap().is_some());
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let got = backend.get(&pkg).await.unwrap();
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
        backend
            .put(&pkg, &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let entries = backend.list_entries(true).await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        let raw = entries[0].raw_vulns.as_ref().unwrap();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].get("id").and_then(|v| v.as_str()), Some("CVE-2023-test"));
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
}
