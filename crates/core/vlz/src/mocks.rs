// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mock implementations for testing run.rs error paths (resolver, CVE provider,
//! database backend). Used by integration tests to exercise uncovered branches.

#![cfg(any(test, feature = "testing"))]

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vlz_cve_client::{CveProvider, FetchedCves, ProviderError};
use vlz_db::{
    CacheEntryInfo, CveRecord, DatabaseBackend, DatabaseError, DatabaseStats,
    Package, TtlSelector,
};
use vlz_manifest_parser::{
    DependencyGraph, ResolveContext, ResolveResult, Resolver, ResolverError,
};

/// Resolver that fails when the manifest path contains a marker substring; otherwise
/// delegates to an inner resolver (FR-037 partial-scan tests).
pub struct ConditionalFailingResolver<R> {
    inner: R,
    path_marker: &'static str,
    failure_message: &'static str,
}

impl<R> ConditionalFailingResolver<R> {
    pub fn new(inner: R, path_marker: &'static str) -> Self {
        Self {
            inner,
            path_marker,
            failure_message: "mock conditional resolve failure",
        }
    }

    fn should_fail(&self, graph: &DependencyGraph) -> bool {
        graph
            .manifest_path
            .as_ref()
            .is_some_and(|p| p.to_string_lossy().contains(self.path_marker))
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for ConditionalFailingResolver<R> {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        if self.should_fail(graph) {
            return Err(ResolverError::Resolve(
                self.failure_message.to_string(),
            ));
        }
        self.inner.resolve(graph, ctx).await
    }

    fn package_manager_available(&self) -> bool {
        self.inner.package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        self.inner.package_manager_hint()
    }

    fn language_name(&self) -> &'static str {
        self.inner.language_name()
    }
}

/// Python resolver that fails only for manifests under a `broken` path segment.
#[cfg(feature = "python")]
pub type PythonConditionalFailingResolver =
    ConditionalFailingResolver<vlz_python::DirectOnlyResolver>;

#[cfg(feature = "python")]
impl PythonConditionalFailingResolver {
    pub fn for_broken_paths() -> Self {
        ConditionalFailingResolver::new(
            vlz_python::DirectOnlyResolver::new(),
            "broken",
        )
    }
}

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
        _ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        Err(ResolverError::Resolve("mock resolve failure".to_string()))
    }

    fn package_manager_available(&self) -> bool {
        true
    }

    fn package_manager_hint(&self) -> &'static str {
        "test mock"
    }

    fn language_name(&self) -> &'static str {
        "mock"
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

    async fn fetch(
        &self,
        pkg: &Package,
    ) -> Result<FetchedCves, ProviderError> {
        let _ = pkg;
        Err(ProviderError::Other("mock fetch failure".to_string()))
    }
}

/// CVE provider that counts fetch calls per (name, version). Used to verify deduplication.
#[derive(Clone)]
pub struct CountingCveProvider {
    counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl CountingCveProvider {
    pub fn new(counts: Arc<Mutex<HashMap<String, usize>>>) -> Self {
        Self { counts }
    }

    pub fn get_counts(&self) -> HashMap<String, usize> {
        self.counts.lock().unwrap().clone()
    }
}

#[async_trait]
impl CveProvider for CountingCveProvider {
    fn name(&self) -> &'static str {
        "counting"
    }

    async fn fetch(
        &self,
        pkg: &Package,
    ) -> Result<FetchedCves, ProviderError> {
        let key = format!("{}::{}", pkg.name, pkg.version);
        {
            let mut counts = self.counts.lock().unwrap();
            *counts.entry(key).or_insert(0) += 1;
        }
        Ok(FetchedCves {
            raw_vulns: vec![],
            records: vec![],
        })
    }
}

/// CVE provider that returns one CVE per package. Used to test report output
/// (e.g. manifest_paths in findings).
#[derive(Debug, Default)]
pub struct CveReturningProvider;

impl CveReturningProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CveProvider for CveReturningProvider {
    fn name(&self) -> &'static str {
        "cve_returning"
    }

    async fn fetch(
        &self,
        _pkg: &Package,
    ) -> Result<FetchedCves, ProviderError> {
        let record = CveRecord {
            id: "CVE-2024-TEST".to_string(),
            cvss_score: Some(7.5),
            cvss_version: Some(vlz_db::CvssVersion::V3),
            description: "Test CVE for manifest_paths".to_string(),
            reachable: None,
        };
        Ok(FetchedCves {
            raw_vulns: vec![serde_json::json!({"id": record.id})],
            records: vec![record],
        })
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

    async fn get(
        &self,
        _: &Package,
        _: &str,
    ) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
        Ok(None)
    }

    async fn get_raw_vulns(
        &self,
        _: &Package,
        _: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, DatabaseError> {
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

    async fn list_entries(
        &self,
        _full: bool,
    ) -> Result<Vec<CacheEntryInfo>, DatabaseError> {
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
        Err(DatabaseError::Other(
            "mock verify_integrity failure".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn conditional_failing_resolver_fails_when_path_contains_marker() {
        let r =
            ConditionalFailingResolver::new(FailingResolver::new(), "broken");
        let graph = DependencyGraph {
            manifest_path: Some(std::path::PathBuf::from(
                "/tmp/broken/requirements.txt",
            )),
            ..Default::default()
        };
        let result = r
            .resolve(&graph, &vlz_manifest_parser::ResolveContext::default())
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mock conditional resolve failure")
        );
    }

    #[tokio::test]
    async fn conditional_failing_resolver_delegates_when_marker_absent() {
        let r =
            ConditionalFailingResolver::new(FailingResolver::new(), "broken");
        let graph = DependencyGraph {
            manifest_path: Some(std::path::PathBuf::from(
                "/tmp/good/requirements.txt",
            )),
            ..Default::default()
        };
        let result = r
            .resolve(&graph, &vlz_manifest_parser::ResolveContext::default())
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mock resolve failure")
        );
    }

    #[tokio::test]
    async fn failing_resolver_resolve_returns_err() {
        let r = FailingResolver::new();
        let graph = DependencyGraph::default();
        let result = r
            .resolve(&graph, &vlz_manifest_parser::ResolveContext::default())
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mock resolve failure")
        );
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
            ecosystem: None,
        };
        let result = p.fetch(&pkg).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mock fetch failure")
        );
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
            ecosystem: None,
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
            ecosystem: None,
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mock set_ttl failure")
        );
    }

    #[tokio::test]
    async fn failing_db_backend_verify_integrity_returns_err() {
        let db = FailingDbBackend::new();
        let result = db.verify_integrity().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mock verify_integrity failure")
        );
    }
}
