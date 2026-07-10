// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared CVE cache warm-up for scan and preload (FR-011, FR-021).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::sync::Semaphore;
use vlz_cve_client::CveProvider;
use vlz_db::{CveRecord, DatabaseBackend, Package};

/// Message returned when `--offline` blocks a cache miss (FR-031).
pub const OFFLINE_CACHE_MISS_MESSAGE: &str = "CVE not found in cache, and unable to lookup CVE due to `--offline` argument.";

/// Options controlling parallel cache warm-up.
#[derive(Debug, Clone)]
pub struct CacheWarmOptions {
    pub parallel: usize,
    pub offline: bool,
    pub benchmark: bool,
}

/// Counts from a cache warm pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheWarmSummary {
    pub packages_checked: usize,
    pub cache_hits: usize,
    pub fetched: usize,
    pub offline_cache_miss: bool,
    pub provider_fetch_failed: bool,
}

/// Result of warming the cache for a package list.
#[derive(Debug, Clone)]
pub struct CacheWarmOutcome {
    pub summary: CacheWarmSummary,
    pub findings: Vec<(Package, Vec<CveRecord>)>,
    pub raw_vulns_by_package: HashMap<Package, Vec<serde_json::Value>>,
}

/// Deduplicate packages by `(name, version)`. Keeps first occurrence.
pub fn deduplicate_packages(packages: &[Package]) -> Vec<Package> {
    let mut seen = std::collections::HashSet::new();
    packages
        .iter()
        .filter(|p| seen.insert((p.name.as_str(), p.version.as_str())))
        .cloned()
        .collect()
}

/// Populate the CVE cache for `packages` using `db` and `provider`.
pub async fn warm_cache_for_packages(
    packages: &[Package],
    db: Arc<Box<dyn DatabaseBackend + Send + Sync + 'static>>,
    provider: Arc<Box<dyn CveProvider + Send + Sync + 'static>>,
    opts: &CacheWarmOptions,
) -> Result<CacheWarmOutcome> {
    let mut summary = CacheWarmSummary {
        packages_checked: packages.len(),
        ..Default::default()
    };
    let mut findings = Vec::new();
    let mut raw_vulns_by_package = HashMap::new();

    if packages.is_empty() {
        return Ok(CacheWarmOutcome {
            summary,
            findings,
            raw_vulns_by_package,
        });
    }

    let semaphore = Arc::new(Semaphore::new(opts.parallel.max(1)));
    let mut handles = Vec::new();
    let benchmark_mode = opts.benchmark;
    let use_network = !(opts.offline || opts.benchmark);

    for pkg in packages {
        let db = db.clone();
        let prov = provider.clone();
        let sem = semaphore.clone();
        let permit = sem.acquire_owned().await.unwrap();
        let pkg = pkg.clone();

        let fut = async move {
            let _guard = permit;

            if benchmark_mode {
                return Ok(WarmPackageResult {
                    pkg: pkg.clone(),
                    records: vec![],
                    raw_vulns: vec![],
                    cache_hit: false,
                    fetched: false,
                });
            }

            if let Some(raw_vulns) =
                db.as_ref().get_raw_vulns(&pkg, prov.name()).await?
            {
                let records =
                    vlz_cve_client::decode_raw_vulns(prov.name(), &raw_vulns);
                return Ok(WarmPackageResult {
                    pkg: pkg.clone(),
                    records,
                    raw_vulns,
                    cache_hit: true,
                    fetched: false,
                });
            }

            if !use_network {
                return Err(anyhow!(OFFLINE_CACHE_MISS_MESSAGE));
            }

            let fetched =
                prov.as_ref().fetch(&pkg).await.with_context(|| {
                    format!("Fetching CVEs for {}@{}", pkg.name, pkg.version)
                })?;
            db.as_ref()
                .put(&pkg, prov.name(), &fetched.raw_vulns, None)
                .await
                .with_context(|| {
                    format!("Storing cache for {}@{}", pkg.name, pkg.version)
                })?;
            Ok(WarmPackageResult {
                pkg: pkg.clone(),
                records: fetched.records,
                raw_vulns: fetched.raw_vulns,
                cache_hit: false,
                fetched: true,
            })
        };

        handles.push(tokio::spawn(fut));
    }

    for h in handles {
        match h.await? {
            Ok(result) => {
                if result.cache_hit {
                    summary.cache_hits += 1;
                }
                if result.fetched {
                    summary.fetched += 1;
                }
                if !result.raw_vulns.is_empty() {
                    raw_vulns_by_package
                        .insert(result.pkg.clone(), result.raw_vulns);
                }
                findings.push((result.pkg, result.records));
            }
            Err(e) => {
                let msg = e.to_string();
                if opts.offline && msg.contains("--offline") {
                    summary.offline_cache_miss = true;
                } else {
                    summary.provider_fetch_failed = true;
                }
            }
        }
    }

    Ok(CacheWarmOutcome {
        summary,
        findings,
        raw_vulns_by_package,
    })
}

struct WarmPackageResult {
    pkg: Package,
    records: Vec<CveRecord>,
    raw_vulns: Vec<serde_json::Value>,
    cache_hit: bool,
    fetched: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use vlz_cve_client::{FetchedCves, ProviderError};
    use vlz_db::{DatabaseError, DatabaseStats, TtlSelector};

    struct MapDb {
        inner: Mutex<HashMap<String, Vec<serde_json::Value>>>,
        fetch_count: Mutex<usize>,
    }

    impl MapDb {
        fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
                fetch_count: Mutex::new(0),
            }
        }

        fn key(pkg: &Package, provider: &str) -> String {
            format!("{}::{}::{}", pkg.name, pkg.version, provider)
        }
    }

    #[async_trait]
    impl DatabaseBackend for MapDb {
        async fn init(&self) -> Result<(), DatabaseError> {
            Ok(())
        }

        async fn get(
            &self,
            pkg: &Package,
            provider_id: &str,
        ) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
            let guard = self.inner.lock().unwrap();
            let key = Self::key(pkg, provider_id);
            Ok(guard
                .get(&key)
                .map(|raw| vlz_cve_client::decode_raw_vulns(provider_id, raw)))
        }

        async fn get_raw_vulns(
            &self,
            pkg: &Package,
            provider_id: &str,
        ) -> Result<Option<Vec<serde_json::Value>>, DatabaseError> {
            let guard = self.inner.lock().unwrap();
            Ok(guard.get(&Self::key(pkg, provider_id)).cloned())
        }

        async fn put(
            &self,
            pkg: &Package,
            provider_id: &str,
            raw_vulns: &[serde_json::Value],
            _ttl_override: Option<u64>,
        ) -> Result<(), DatabaseError> {
            *self.fetch_count.lock().unwrap() += 1;
            self.inner
                .lock()
                .unwrap()
                .insert(Self::key(pkg, provider_id), raw_vulns.to_vec());
            Ok(())
        }

        async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
            Ok(DatabaseStats::default())
        }

        async fn set_ttl(
            &self,
            _selector: TtlSelector,
            _new_ttl_secs: u64,
        ) -> Result<(), DatabaseError> {
            Ok(())
        }

        async fn verify_integrity(&self) -> Result<(), DatabaseError> {
            Ok(())
        }
    }

    struct StaticProvider {
        name: &'static str,
        calls: Arc<Mutex<usize>>,
    }

    #[async_trait]
    impl CveProvider for StaticProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn fetch(
            &self,
            _pkg: &Package,
        ) -> Result<FetchedCves, ProviderError> {
            *self.calls.lock().unwrap() += 1;
            Ok(FetchedCves {
                raw_vulns: vec![serde_json::json!({"id": "CVE-TEST-1"})],
                records: vec![CveRecord {
                    id: "CVE-TEST-1".to_string(),
                    cvss_score: None,
                    cvss_version: None,
                    description: "test".to_string(),
                    reachable: None,
                }],
            })
        }
    }

    fn sample_pkg() -> Package {
        Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("PyPI".to_string()),
        }
    }

    #[tokio::test]
    async fn warm_cache_miss_fetches_and_puts() {
        let db = Arc::new(Box::new(MapDb::new())
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        let calls = Arc::new(Mutex::new(0));
        let provider = Arc::new(Box::new(StaticProvider {
            name: "test",
            calls: calls.clone(),
        })
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: false,
            benchmark: false,
        };
        let outcome =
            warm_cache_for_packages(&[sample_pkg()], db, provider, &opts)
                .await
                .unwrap();
        assert_eq!(outcome.summary.fetched, 1);
        assert_eq!(outcome.summary.cache_hits, 0);
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(outcome.findings[0].1[0].id, "CVE-TEST-1");
    }

    #[tokio::test]
    async fn warm_cache_hit_skips_fetch() {
        let db = Arc::new(Box::new(MapDb::new())
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        db.put(
            &sample_pkg(),
            "test",
            &[serde_json::json!({"id": "CVE-CACHED"})],
            None,
        )
        .await
        .unwrap();
        let calls = Arc::new(Mutex::new(0));
        let provider = Arc::new(Box::new(StaticProvider {
            name: "test",
            calls: calls.clone(),
        })
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: false,
            benchmark: false,
        };
        let outcome =
            warm_cache_for_packages(&[sample_pkg()], db, provider, &opts)
                .await
                .unwrap();
        assert_eq!(outcome.summary.cache_hits, 1);
        assert_eq!(outcome.summary.fetched, 0);
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn warm_cache_offline_miss_sets_flag() {
        let db = Arc::new(Box::new(MapDb::new())
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        let calls = Arc::new(Mutex::new(0));
        let provider = Arc::new(Box::new(StaticProvider {
            name: "test",
            calls,
        })
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: true,
            benchmark: false,
        };
        let outcome =
            warm_cache_for_packages(&[sample_pkg()], db, provider, &opts)
                .await
                .unwrap();
        assert!(outcome.summary.offline_cache_miss);
        assert!(outcome.findings.is_empty());
    }

    #[test]
    fn deduplicate_packages_keeps_first() {
        let a = sample_pkg();
        let mut b = sample_pkg();
        b.version = "2.0".to_string();
        let out = deduplicate_packages(&[a.clone(), a, b.clone()]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].version, "1.0");
        assert_eq!(out[1].version, "2.0");
    }

    #[tokio::test]
    async fn warm_cache_empty_packages_returns_defaults() {
        let db = Arc::new(Box::new(MapDb::new())
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        let provider = Arc::new(Box::new(StaticProvider {
            name: "test",
            calls: Arc::new(Mutex::new(0)),
        })
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: false,
            benchmark: false,
        };
        let outcome = warm_cache_for_packages(&[], db, provider, &opts)
            .await
            .unwrap();
        assert_eq!(outcome.summary.packages_checked, 0);
        assert!(outcome.findings.is_empty());
    }

    #[tokio::test]
    async fn warm_cache_benchmark_skips_network_and_db() {
        let db = Arc::new(Box::new(MapDb::new())
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        let calls = Arc::new(Mutex::new(0));
        let provider = Arc::new(Box::new(StaticProvider {
            name: "test",
            calls: calls.clone(),
        })
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: false,
            benchmark: true,
        };
        let outcome =
            warm_cache_for_packages(&[sample_pkg()], db, provider, &opts)
                .await
                .unwrap();
        assert_eq!(outcome.summary.packages_checked, 1);
        assert_eq!(outcome.summary.fetched, 0);
        assert_eq!(outcome.summary.cache_hits, 0);
        assert_eq!(*calls.lock().unwrap(), 0);
        assert!(outcome.findings[0].1.is_empty());
    }

    struct FailingPutDb(MapDb);

    #[async_trait]
    impl DatabaseBackend for FailingPutDb {
        async fn init(&self) -> Result<(), DatabaseError> {
            self.0.init().await
        }

        async fn get(
            &self,
            pkg: &Package,
            provider_id: &str,
        ) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
            self.0.get(pkg, provider_id).await
        }

        async fn get_raw_vulns(
            &self,
            pkg: &Package,
            provider_id: &str,
        ) -> Result<Option<Vec<serde_json::Value>>, DatabaseError> {
            self.0.get_raw_vulns(pkg, provider_id).await
        }

        async fn put(
            &self,
            _pkg: &Package,
            _provider_id: &str,
            _raw_vulns: &[serde_json::Value],
            _ttl_override: Option<u64>,
        ) -> Result<(), DatabaseError> {
            Err(DatabaseError::Storage {
                message: "simulated put failure".to_string(),
                source: Box::new(std::io::Error::other("put failed")),
            })
        }

        async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
            self.0.stats().await
        }

        async fn set_ttl(
            &self,
            selector: TtlSelector,
            new_ttl_secs: u64,
        ) -> Result<(), DatabaseError> {
            self.0.set_ttl(selector, new_ttl_secs).await
        }

        async fn verify_integrity(&self) -> Result<(), DatabaseError> {
            self.0.verify_integrity().await
        }
    }

    struct FailingProvider;

    #[async_trait]
    impl CveProvider for FailingProvider {
        fn name(&self) -> &'static str {
            "fail"
        }

        async fn fetch(
            &self,
            pkg: &Package,
        ) -> Result<FetchedCves, ProviderError> {
            Err(ProviderError::Other(format!(
                "fetch failed for {}",
                pkg.name
            )))
        }
    }

    #[tokio::test]
    async fn warm_cache_provider_failure_sets_flag() {
        let db = Arc::new(Box::new(MapDb::new())
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        let provider = Arc::new(Box::new(FailingProvider)
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: false,
            benchmark: false,
        };
        let outcome =
            warm_cache_for_packages(&[sample_pkg()], db, provider, &opts)
                .await
                .unwrap();
        assert!(outcome.summary.provider_fetch_failed);
        assert!(outcome.findings.is_empty());
    }

    #[tokio::test]
    async fn warm_cache_put_failure_sets_provider_fetch_failed() {
        let db = Arc::new(Box::new(FailingPutDb(MapDb::new()))
            as Box<dyn DatabaseBackend + Send + Sync + 'static>);
        let provider = Arc::new(Box::new(StaticProvider {
            name: "test",
            calls: Arc::new(Mutex::new(0)),
        })
            as Box<dyn CveProvider + Send + Sync + 'static>);
        let opts = CacheWarmOptions {
            parallel: 1,
            offline: false,
            benchmark: false,
        };
        let outcome =
            warm_cache_for_packages(&[sample_pkg()], db, provider, &opts)
                .await
                .unwrap();
        assert!(outcome.summary.provider_fetch_failed);
    }

    #[tokio::test]
    async fn map_db_trait_methods_smoke() {
        let db = MapDb::new();
        db.init().await.unwrap();
        assert!(db.get(&sample_pkg(), "test").await.unwrap().is_none());
        db.stats().await.unwrap();
        db.set_ttl(TtlSelector::All, 60).await.unwrap();
        db.verify_integrity().await.unwrap();
    }
}
