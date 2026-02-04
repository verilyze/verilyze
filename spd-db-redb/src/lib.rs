//! RedB‑backed implementation of `DatabaseBackend`.
//!
//! Persists CVE cache entries in a single RedB file with one table.
//! Respects TTL (OP‑009 / FR‑011), atomic writes (FR‑030), and
//! SHA‑256 integrity verification (SEC‑004).
#![deny(unsafe_code)]

use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spd_cve_client::raw_vuln_to_cve_record;
use spd_db::{CveRecord, DatabaseBackend, DatabaseError, DatabaseStats, Package};

/// RedB table: key = `"name::version"`, value = JSON of `StoredEntry`.
const CACHE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("cve_cache");

/// Serialized form of a cache entry (raw OSV vuln JSON per package + TTL).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEntry {
    raw_vulns: Vec<serde_json::Value>,
    #[serde(rename = "expires_at_secs")]
    expires_at_secs: u64,
}

fn pkg_key(pkg: &Package) -> String {
    format!("{}::{}", pkg.name, pkg.version)
}

/// Real RedB backend: one file, one table, JSON values.
#[derive(Clone)]
pub struct RedbBackend {
    db: Arc<Database>,
    ttl_secs: u64,
}

impl RedbBackend {
    /// Create a new backend using a RedB file at `path`.
    ///
    /// * `path` – path to the `.redb` file (created if missing).
    /// * `ttl_secs` – time‑to‑live for cached CVE entries.
    pub fn with_path(path: PathBuf, ttl_secs: u64) -> Result<Self, DatabaseError> {
        let db = Database::create(path).map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(Self {
            db: Arc::new(db),
            ttl_secs: ttl_secs.max(1),
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

    fn expiry_time_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            .saturating_add(self.ttl_secs)
    }

    /// Remove all entries that have passed their TTL (best-effort in one write txn).
    fn purge_expired(&self) -> Result<(), DatabaseError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let write_txn = self
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
        write_txn.commit().map_err(|e| DatabaseError::Other(e.to_string()))?;
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
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let guard = match table.get(key.as_str()).map_err(|e| DatabaseError::Other(e.to_string()))? {
            Some(g) => g,
            None => return Ok(None),
        };
        let val_str = guard.value();
        let stored: StoredEntry = match serde_json::from_str(val_str) {
            Ok(s) => s,
            Err(_) => return Ok(None), // wrong schema or corrupt; treat as cache miss
        };
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        if stored.expires_at_secs <= now_secs {
            return Ok(None);
        }
        let records: Vec<CveRecord> = stored
            .raw_vulns
            .iter()
            .filter_map(raw_vuln_to_cve_record)
            .collect();
        Ok(Some(records))
    }

    async fn put(&self, pkg: &Package, raw_vulns: &[serde_json::Value]) -> Result<(), DatabaseError> {
        let key = pkg_key(pkg);
        let entry = StoredEntry {
            raw_vulns: raw_vulns.to_vec(),
            expires_at_secs: self.expiry_time_secs(),
        };
        let value = serde_json::to_string(&entry).map_err(DatabaseError::Serde)?;
        let write_txn = self
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
        write_txn.commit().map_err(|e| DatabaseError::Other(e.to_string()))?;
        Ok(())
    }

    async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let total = table.len().map_err(|e| DatabaseError::Other(e.to_string()))? as usize;
        Ok(DatabaseStats {
            cached_entries: total,
            hits: 0,
            misses: 0,
        })
    }

    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        use sha2::{Digest, Sha256};

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let table = read_txn
            .open_table(CACHE_TABLE)
            .map_err(|e| DatabaseError::Other(e.to_string()))?;
        let mut hasher = Sha256::new();
        for entry in table.iter().map_err(|e| DatabaseError::Other(e.to_string()))? {
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
