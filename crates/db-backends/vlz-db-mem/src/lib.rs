// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

//! In-memory CVE cache backend for ephemeral scans (process-local only).

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use vlz_cve_client::decode_raw_vulns;
use vlz_db::{
    CacheEntryInfo, CveRecord, DatabaseBackend, DatabaseError, DatabaseStats,
    Package, StoredEntry, TtlSelector, entry_is_expired, new_stored_entry,
    normalize_stored_entry, pkg_cache_key, unix_now_secs,
};

struct MemBackendInner {
    entries: RwLock<HashMap<String, StoredEntry>>,
    ttl_secs: u64,
    hits: AtomicUsize,
    misses: AtomicUsize,
}

/// Process-local CVE cache (`HashMap` + `RwLock`).
#[derive(Clone)]
pub struct MemBackend {
    inner: Arc<MemBackendInner>,
}

impl MemBackend {
    /// Create a backend with the given default TTL (clamped to at least 1 second).
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(MemBackendInner {
                entries: RwLock::new(HashMap::new()),
                ttl_secs: ttl_secs.max(1),
                hits: AtomicUsize::new(0),
                misses: AtomicUsize::new(0),
            }),
        }
    }

    fn purge_expired_locked(
        entries: &mut HashMap<String, StoredEntry>,
        now_secs: u64,
    ) {
        entries.retain(|_, e| !entry_is_expired(e, now_secs));
    }
}

#[async_trait]
impl DatabaseBackend for MemBackend {
    async fn init(&self) -> Result<(), DatabaseError> {
        vlz_cve_client::ensure_default_decoders();
        let now = unix_now_secs();
        let mut guard = self.inner.entries.write().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        Self::purge_expired_locked(&mut guard, now);
        Ok(())
    }

    async fn get(
        &self,
        pkg: &Package,
        provider_id: &str,
    ) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
        vlz_cve_client::ensure_default_decoders();
        let key = pkg_cache_key(pkg, provider_id);
        let now = unix_now_secs();
        let guard = self.inner.entries.read().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        let Some(mut stored) = guard.get(&key).cloned() else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        normalize_stored_entry(&mut stored, self.inner.ttl_secs);
        if entry_is_expired(&stored, now) {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let records = decode_raw_vulns(&stored.provider_id, &stored.raw_vulns);
        self.inner.hits.fetch_add(1, Ordering::Relaxed);
        Ok(Some(records))
    }

    async fn get_raw_vulns(
        &self,
        pkg: &Package,
        provider_id: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, DatabaseError> {
        let key = pkg_cache_key(pkg, provider_id);
        let now = unix_now_secs();
        let guard = self.inner.entries.read().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        let Some(mut stored) = guard.get(&key).cloned() else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        normalize_stored_entry(&mut stored, self.inner.ttl_secs);
        if entry_is_expired(&stored, now) {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        self.inner.hits.fetch_add(1, Ordering::Relaxed);
        Ok(Some(stored.raw_vulns))
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
        let entry =
            new_stored_entry(provider_id, raw_vulns, ttl, unix_now_secs());
        let mut guard = self.inner.entries.write().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        guard.insert(key, entry);
        Ok(())
    }

    async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
        let guard = self.inner.entries.read().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        Ok(DatabaseStats {
            cached_entries: guard.len(),
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
            cache_ttl_secs: Some(self.inner.ttl_secs),
        })
    }

    async fn list_entries(
        &self,
        full: bool,
    ) -> Result<Vec<CacheEntryInfo>, DatabaseError> {
        vlz_cve_client::ensure_default_decoders();
        let guard = self.inner.entries.read().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        let mut out = Vec::new();
        for (key, stored) in guard.iter() {
            let mut stored = stored.clone();
            normalize_stored_entry(&mut stored, self.inner.ttl_secs);
            let records =
                decode_raw_vulns(&stored.provider_id, &stored.raw_vulns);
            let cve_ids: Vec<String> =
                records.iter().map(|r| r.id.clone()).collect();
            out.push(CacheEntryInfo {
                key: key.clone(),
                ttl_secs: stored.ttl_secs.unwrap_or(self.inner.ttl_secs),
                added_at_secs: stored.added_at_secs.unwrap_or(0),
                cve_count: stored.raw_vulns.len(),
                cve_ids,
                raw_vulns: if full {
                    Some(stored.raw_vulns.clone())
                } else {
                    None
                },
            });
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    async fn set_ttl(
        &self,
        selector: TtlSelector,
        new_ttl_secs: u64,
    ) -> Result<(), DatabaseError> {
        let new_ttl = new_ttl_secs.max(1);
        let mut guard = self.inner.entries.write().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        let keys: Vec<String> = match &selector {
            TtlSelector::One(k) => vec![k.clone()],
            TtlSelector::Multiple(keys) => keys.clone(),
            TtlSelector::All => guard.keys().cloned().collect(),
        };
        for key in keys {
            let Some(stored) = guard.get_mut(&key) else {
                continue;
            };
            normalize_stored_entry(stored, self.inner.ttl_secs);
            let added = stored.added_at_secs.unwrap_or(0);
            stored.expires_at_secs = added.saturating_add(new_ttl);
            stored.ttl_secs = Some(new_ttl);
        }
        Ok(())
    }

    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        let guard = self.inner.entries.read().map_err(|_| {
            DatabaseError::Other("mem cache lock poisoned".into())
        })?;
        let mut keys: Vec<_> = guard.keys().cloned().collect();
        keys.sort();
        let mut hasher = Sha256::new();
        for key in keys {
            let val = serde_json::to_string(guard.get(&key).unwrap())
                .map_err(DatabaseError::Serde)?;
            hasher.update(format!("{key}|{val}").as_bytes());
        }
        let _hash = hasher.finalize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_raw_vuln() -> serde_json::Value {
        serde_json::json!({
            "id": "CVE-2023-test",
            "database_specific": { "cvss_v3_score": 7.0 },
            "summary": "Test vuln"
        })
    }

    #[tokio::test]
    async fn put_get_stats() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let pkg = Package {
            name: "mem_pkg".into(),
            version: "1.0".into(),
            ecosystem: None,
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let got = backend.get(&pkg, "osv").await.unwrap().unwrap();
        assert_eq!(got[0].id, "CVE-2023-test");
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.cached_entries, 1);
        assert!(stats.hits >= 1);
    }

    #[tokio::test]
    async fn expired_entry_is_miss() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let pkg = Package {
            name: "e".into(),
            version: "1".into(),
            ecosystem: None,
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], Some(1))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(backend.get(&pkg, "osv").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_ttl_and_list_entries() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let pkg = Package {
            name: "a".into(),
            version: "1".into(),
            ecosystem: None,
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::One("a::1::osv".into()), 120)
            .await
            .unwrap();
        let entries = backend.list_entries(true).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_secs, 120);
        assert!(entries[0].raw_vulns.is_some());
    }

    #[tokio::test]
    async fn verify_integrity_ok() {
        let backend = MemBackend::new(60);
        backend.init().await.unwrap();
        backend.verify_integrity().await.unwrap();
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let backend = MemBackend::new(3600);
        let pkg = Package {
            name: "shared".into(),
            version: "1".into(),
            ecosystem: None,
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let clone = backend.clone();
        assert!(clone.get(&pkg, "osv").await.unwrap().is_some());
    }
}
