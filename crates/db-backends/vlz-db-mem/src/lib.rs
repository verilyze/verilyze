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

const POISONED_LOCK: &str = "mem cache lock poisoned";

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

    fn read_entries(
        &self,
    ) -> Result<
        std::sync::RwLockReadGuard<'_, HashMap<String, StoredEntry>>,
        DatabaseError,
    > {
        self.inner
            .entries
            .read()
            .map_err(|_| DatabaseError::Other(POISONED_LOCK.into()))
    }

    fn write_entries(
        &self,
    ) -> Result<
        std::sync::RwLockWriteGuard<'_, HashMap<String, StoredEntry>>,
        DatabaseError,
    > {
        self.inner
            .entries
            .write()
            .map_err(|_| DatabaseError::Other(POISONED_LOCK.into()))
    }

    #[cfg(test)]
    fn poison_lock_for_test(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = std::thread::spawn(move || {
            let _guard = inner.entries.write().unwrap();
            panic!("intentional mem cache lock poison");
        })
        .join();
    }
}

#[async_trait]
impl DatabaseBackend for MemBackend {
    async fn init(&self) -> Result<(), DatabaseError> {
        vlz_cve_client::ensure_default_decoders();
        let now = unix_now_secs();
        let mut guard = self.write_entries()?;
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
        let guard = self.read_entries()?;
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
        let guard = self.read_entries()?;
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
        let mut guard = self.write_entries()?;
        guard.insert(key, entry);
        Ok(())
    }

    async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
        let guard = self.read_entries()?;
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
        let guard = self.read_entries()?;
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
        let mut guard = self.write_entries()?;
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
        let guard = self.read_entries()?;
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

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            ecosystem: None,
        }
    }

    #[tokio::test]
    async fn put_get_stats() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let p = pkg("mem_pkg", "1.0");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let got = backend.get(&p, "osv").await.unwrap().unwrap();
        assert_eq!(got[0].id, "CVE-2023-test");
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.cached_entries, 1);
        assert!(stats.hits >= 1);
        assert_eq!(stats.cache_ttl_secs, Some(3600));
    }

    #[tokio::test]
    async fn ttl_zero_clamped_to_one() {
        let backend = MemBackend::new(0);
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.cache_ttl_secs, Some(1));
    }

    #[tokio::test]
    async fn get_unknown_is_miss() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let p = pkg("missing", "0");
        assert!(backend.get(&p, "osv").await.unwrap().is_none());
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn get_raw_vulns_hit_and_miss() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let p = pkg("raw", "1.0");
        assert!(backend.get_raw_vulns(&p, "osv").await.unwrap().is_none());
        backend
            .put(&p, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let raw = backend.get_raw_vulns(&p, "osv").await.unwrap().unwrap();
        assert_eq!(raw[0]["id"], "CVE-2023-test");
        let stats = backend.stats().await.unwrap();
        assert!(stats.hits >= 1);
        assert!(stats.misses >= 1);
    }

    #[tokio::test]
    async fn expired_entry_is_miss() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let p = pkg("e", "1");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], Some(1))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(backend.get(&p, "osv").await.unwrap().is_none());
        assert!(backend.get_raw_vulns(&p, "osv").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn init_purges_expired_entries() {
        let backend = MemBackend::new(3600);
        let p = pkg("purge", "1");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], Some(1))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        backend.init().await.unwrap();
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.cached_entries, 0);
    }

    #[tokio::test]
    async fn set_ttl_and_list_entries() {
        let backend = MemBackend::new(3600);
        backend.init().await.unwrap();
        let p = pkg("a", "1");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], None)
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
        let slim = backend.list_entries(false).await.unwrap();
        assert!(slim[0].raw_vulns.is_none());
    }

    #[tokio::test]
    async fn set_ttl_all_and_multiple() {
        let backend = MemBackend::new(3600);
        let a = pkg("a", "1");
        let b = pkg("b", "1");
        backend
            .put(&a, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend
            .put(&b, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend.set_ttl(TtlSelector::All, 50).await.unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        assert!(entries.iter().all(|e| e.ttl_secs == 50));
        backend
            .set_ttl(
                TtlSelector::Multiple(vec![
                    "a::1::osv".into(),
                    "missing::9::osv".into(),
                ]),
                90,
            )
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        let a_entry = entries.iter().find(|e| e.key == "a::1::osv").unwrap();
        assert_eq!(a_entry.ttl_secs, 90);
        backend
            .set_ttl(TtlSelector::One("nope::0::osv".into()), 1)
            .await
            .unwrap();
        backend
            .set_ttl(TtlSelector::Multiple(vec![]), 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn put_ttl_override_zero_clamped() {
        let backend = MemBackend::new(3600);
        let p = pkg("clamp", "1");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], Some(0))
            .await
            .unwrap();
        let entries = backend.list_entries(false).await.unwrap();
        assert_eq!(entries[0].ttl_secs, 1);
    }

    #[tokio::test]
    async fn verify_integrity_with_entries() {
        let backend = MemBackend::new(60);
        backend.init().await.unwrap();
        let p = pkg("v", "1");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        backend.verify_integrity().await.unwrap();
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let backend = MemBackend::new(3600);
        let p = pkg("shared", "1");
        backend
            .put(&p, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let clone = backend.clone();
        assert!(clone.get(&p, "osv").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn poisoned_lock_errors_on_ops() {
        let backend = MemBackend::new(60);
        let p = pkg("p", "1");
        backend.poison_lock_for_test();
        assert!(backend.init().await.is_err());
        assert!(backend.get(&p, "osv").await.is_err());
        assert!(backend.get_raw_vulns(&p, "osv").await.is_err());
        assert!(
            backend
                .put(&p, "osv", &[sample_raw_vuln()], None)
                .await
                .is_err()
        );
        assert!(backend.stats().await.is_err());
        assert!(backend.list_entries(false).await.is_err());
        assert!(backend.set_ttl(TtlSelector::All, 1).await.is_err());
        assert!(backend.verify_integrity().await.is_err());
    }
}
