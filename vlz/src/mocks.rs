// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mock implementations for testing run.rs error paths (resolver, CVE provider,
//! database backend). Used by integration tests to exercise uncovered branches.

#![cfg(any(test, feature = "testing"))]

use async_trait::async_trait;
use vlz_cve_client::{CveProvider, FetchedCves, ProviderError};
use vlz_db::{
    CacheEntryInfo, CveRecord, DatabaseBackend, DatabaseError, DatabaseStats, Package,
    TtlSelector,
};
use vlz_manifest_parser::{DependencyGraph, Resolver, ResolverError};

/// Resolver that always returns an error. Covers resolve `with_context` (557-558).
#[derive(Debug, Default)]
pub struct FailingResolver;

impl FailingResolver {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Resolver for FailingResolver {
    async fn resolve(
        &self,
        _graph: &DependencyGraph,
    ) -> Result<Vec<Package>, ResolverError> {
        Err(ResolverError::Resolve("mock resolve failure".to_string()))
    }

    fn package_manager_available(&self) -> bool {
        true
    }

    fn package_manager_hint(&self) -> &'static str {
        "test mock"
    }
}

/// CVE provider that always returns an error. Covers fetch `with_context`
/// (586-587) and Err + verbosity (654-663).
#[derive(Debug, Default)]
pub struct FailingCveProvider;

impl FailingCveProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CveProvider for FailingCveProvider {
    fn name(&self) -> &'static str {
        "failing"
    }

    async fn fetch(&self, pkg: &Package) -> Result<FetchedCves, ProviderError> {
        let _ = pkg;
        Err(ProviderError::Other("mock fetch failure".to_string()))
    }
}

/// Database backend where verify_integrity and set_ttl fail. Covers 335-336,
/// 407-409.
#[derive(Debug, Default)]
pub struct FailingDbBackend;

impl FailingDbBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DatabaseBackend for FailingDbBackend {
    async fn init(&self) -> Result<(), DatabaseError> {
        Ok(())
    }

    async fn get(&self, _: &Package, _: &str) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
        Ok(None)
    }

    async fn put(
        &self,
        _: &Package,
        _: &str,
        _: &[serde_json::Value],
        _: Option<u64>,
    ) -> Result<(), DatabaseError> {
        Ok(())
    }

    async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
        Ok(DatabaseStats::default())
    }

    async fn list_entries(&self, _full: bool) -> Result<Vec<CacheEntryInfo>, DatabaseError> {
        Ok(vec![])
    }

    async fn set_ttl(
        &self,
        _selector: TtlSelector,
        _new_ttl_secs: u64,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Other("mock set_ttl failure".to_string()))
    }

    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        Err(DatabaseError::Other("mock verify_integrity failure".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failing_resolver_resolve_returns_err() {
        let r = FailingResolver::new();
        let graph = DependencyGraph::default();
        let result = r.resolve(&graph).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mock resolve failure"));
    }

    #[test]
    fn failing_resolver_package_manager_available() {
        let r = FailingResolver::new();
        assert!(r.package_manager_available());
        assert_eq!(r.package_manager_hint(), "test mock");
    }

    #[tokio::test]
    async fn failing_cve_provider_fetch_returns_err() {
        let p = FailingCveProvider::new();
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
        };
        let result = p.fetch(&pkg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mock fetch failure"));
    }

    #[test]
    fn failing_cve_provider_name() {
        let p = FailingCveProvider::new();
        assert_eq!(p.name(), "failing");
    }

    #[tokio::test]
    async fn failing_db_backend_init_ok() {
        let db = FailingDbBackend::new();
        assert!(db.init().await.is_ok());
    }

    #[tokio::test]
    async fn failing_db_backend_get_returns_none() {
        let db = FailingDbBackend::new();
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
        };
        let result = db.get(&pkg, "osv").await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn failing_db_backend_put_ok() {
        let db = FailingDbBackend::new();
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
        };
        let raw = vec![serde_json::json!({"id": "CVE-X"})];
        assert!(db.put(&pkg, "osv", &raw, None).await.is_ok());
    }

    #[tokio::test]
    async fn failing_db_backend_stats_returns_default() {
        let db = FailingDbBackend::new();
        let result = db.stats().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().cached_entries, 0);
    }

    #[tokio::test]
    async fn failing_db_backend_list_entries_returns_empty() {
        let db = FailingDbBackend::new();
        let result = db.list_entries(false).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn failing_db_backend_set_ttl_returns_err() {
        let db = FailingDbBackend::new();
        let result = db.set_ttl(TtlSelector::One("k".to_string()), 3600).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mock set_ttl failure"));
    }

    #[tokio::test]
    async fn failing_db_backend_verify_integrity_returns_err() {
        let db = FailingDbBackend::new();
        let result = db.verify_integrity().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mock verify_integrity failure"));
    }
}
