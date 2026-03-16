// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
//use std::path::PathBuf;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    Default,
)]
pub struct Package {
    pub name: String,
    pub version: String,

    /// Ecosystem for CVE lookup (e.g. "PyPI", "crates.io"). When None, providers default to PyPI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
}

/// CVSS version used for the primary score (FR-034).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum CvssVersion {
    V2,
    V3,
    V4,
}

/// Severity label for display in reports (FR-013). Derived from primary CVSS score + configurable thresholds.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    /// Display label for reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CveRecord {
    pub id: String,
    /// Primary CVSS score (latest version available; FR-034).
    pub cvss_score: Option<f32>,
    /// CVSS version used for cvss_score.
    pub cvss_version: Option<CvssVersion>,
    pub description: String,
    pub reachable: Option<bool>, // filled later by reachability analysis
                                 // …more fields as needed
}

#[derive(Debug, Default)]
pub struct DatabaseStats {
    pub cached_entries: usize,
    pub hits: usize,
    pub misses: usize,
    /// TTL in seconds used by this backend (if reported).
    pub cache_ttl_secs: Option<u64>,
}

/// Errors that can bubble up from any backend implementation.
#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Storage/backend error with source preserved for verbose mode (NFR-018).
    #[error("Storage error: {message}")]
    Storage {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("{0}")]
    Other(String),
}

impl DatabaseError {
    /// Wrap an error while preserving its source chain (NFR-018).
    pub fn wrap<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        let message = e.to_string();
        DatabaseError::Storage {
            message,
            source: Box::new(e),
        }
    }
}

/// Trait for false-positive (ignore) database backends (FR-015).
/// Any backend (RedB, SQLite, etc.) must implement this contract so that
/// project_id-scoped filtering works consistently across implementations.
pub trait IgnoreDb: Send + Sync {
    /// Mark a CVE as false positive.
    fn mark(
        &self,
        cve_id: &str,
        comment: &str,
        project_id: Option<&str>,
    ) -> Result<(), DatabaseError>;

    /// Remove a false-positive marking.
    fn unmark(&self, cve_id: &str) -> Result<(), DatabaseError>;

    /// Return true if the CVE is marked as false positive.
    fn is_marked(&self, cve_id: &str) -> Result<bool, DatabaseError>;

    /// Return CVE IDs marked as false positive for the given project.
    /// When `project_id` is None, returns only global FPs (entries with no project_id).
    /// When `project_id` is Some(x), returns global FPs plus FPs scoped to project x.
    fn marked_ids(
        &self,
        project_id: Option<&str>,
    ) -> Result<std::collections::HashSet<String>, DatabaseError>;
}

/// SEC-014: Returns Err if the file at path exists and is world-writable.
/// Call before opening a cache or ignore DB file. Group or other write bits
/// (0o022) indicate world-writable.
pub fn reject_world_writable_db(
    path: &std::path::Path,
) -> Result<(), DatabaseError> {
    if !path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(DatabaseError::Io)?;
        let mode = meta.permissions().mode();
        if (mode & 0o022) != 0 {
            return Err(DatabaseError::Other(
                "Database file cannot be opened or is world-writable. \
                 Fix file permissions (e.g. chmod 0640) or use a different path."
                    .into(),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Summary of a single cache entry (FR-035, OP-009).
/// When `raw_vulns` is `Some`, the entry includes the full CVE payload (e.g.
/// for `vlz db show --full`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CacheEntryInfo {
    pub key: String,
    pub ttl_secs: u64,
    pub added_at_secs: u64,
    pub cve_count: usize,
    pub cve_ids: Vec<String>,
    /// Full raw OSV vuln list when requested (e.g. list_entries(full: true)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_vulns: Option<Vec<serde_json::Value>>,
}

/// Selector for which cache entries to update TTL (OP-015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlSelector {
    /// Single entry by package key (e.g. "name::version").
    One(String),
    /// Multiple entries by explicit keys.
    Multiple(Vec<String>),
    /// All entries.
    All,
}

#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    /// Initialise the backend (create files, run migrations, …).
    async fn init(&self) -> Result<(), DatabaseError>;

    /// Retrieve all cached CVE records for a package from the given provider, if present.
    async fn get(
        &self,
        pkg: &Package,
        provider_id: &str,
    ) -> Result<Option<Vec<CveRecord>>, DatabaseError>;

    /// Store freshly-fetched raw CVE vuln JSON for a package from the given provider
    /// (replaces any existing entry). If `ttl_override` is Some, that entry uses
    /// that TTL instead of the backend default.
    async fn put(
        &self,
        pkg: &Package,
        provider_id: &str,
        raw_vulns: &[serde_json::Value],
        ttl_override: Option<u64>,
    ) -> Result<(), DatabaseError>;

    /// Return simple statistics (used by `vlz db stats`).
    async fn stats(&self) -> Result<DatabaseStats, DatabaseError>;

    /// List cache entries with key, TTL, added_at, and summary (FR-035).
    /// If `full` is true, entries include full CVE payload in `raw_vulns`.
    /// Default returns empty list for backends that do not support listing.
    async fn list_entries(
        &self,
        full: bool,
    ) -> Result<Vec<CacheEntryInfo>, DatabaseError> {
        let _ = (self, full);
        Ok(vec![])
    }

    /// Update TTL for existing entries (OP-015). Default returns error for
    /// backends that do not support updates.
    async fn set_ttl(
        &self,
        _selector: TtlSelector,
        _new_ttl_secs: u64,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Other("set_ttl not supported".into()))
    }

    /// Verify integrity of the underlying storage.
    ///
    /// The default implementation simply returns `Ok(())`.  Concrete
    /// back‑ends may override it (e.g. SHA‑256, FIPS‑204).
    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_as_str_fr013() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");
        assert_eq!(Severity::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn package_construction_and_serde() {
        let p = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: None,
        };
        assert_eq!(p.name, "foo");
        assert_eq!(p.version, "1.0.0");
        let json = serde_json::to_string(&p).unwrap();
        let q: Package = serde_json::from_str(&json).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn cve_record_construction_and_serde() {
        let c = CveRecord {
            id: "CVE-2023-1234".to_string(),
            cvss_score: Some(7.5),
            cvss_version: Some(CvssVersion::V3),
            description: "desc".to_string(),
            reachable: Some(false),
        };
        assert_eq!(c.id, "CVE-2023-1234");
        assert_eq!(c.cvss_score, Some(7.5));
        let json = serde_json::to_string(&c).unwrap();
        let d: CveRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(c.id, d.id);
        assert_eq!(c.cvss_score, d.cvss_score);
    }

    #[test]
    fn cvss_version_serde_roundtrip() {
        for v in [CvssVersion::V2, CvssVersion::V3, CvssVersion::V4] {
            let json = serde_json::to_string(&v).unwrap();
            let w: CvssVersion = serde_json::from_str(&json).unwrap();
            assert_eq!(v, w);
        }
    }

    #[test]
    fn database_stats_default() {
        let s = DatabaseStats::default();
        assert_eq!(s.cached_entries, 0);
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0);
        assert_eq!(s.cache_ttl_secs, None);
    }

    struct MockBackend;

    #[async_trait::async_trait]
    impl DatabaseBackend for MockBackend {
        async fn init(&self) -> Result<(), DatabaseError> {
            Ok(())
        }
        async fn get(
            &self,
            _pkg: &Package,
            _provider_id: &str,
        ) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
            Ok(None)
        }
        async fn put(
            &self,
            _pkg: &Package,
            _provider_id: &str,
            _raw_vulns: &[serde_json::Value],
            _ttl_override: Option<u64>,
        ) -> Result<(), DatabaseError> {
            Ok(())
        }
        async fn stats(&self) -> Result<DatabaseStats, DatabaseError> {
            Ok(DatabaseStats::default())
        }
    }

    #[tokio::test]
    async fn mock_backend_init_get_put_stats() {
        let backend = MockBackend;
        let pkg = Package {
            name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: None,
        };

        backend.init().await.unwrap();
        let got = backend.get(&pkg, "osv").await.unwrap();
        assert!(got.is_none());
        backend
            .put(
                &pkg,
                "osv",
                &[serde_json::json!({"id": "CVE-2024-0001"})],
                None,
            )
            .await
            .unwrap();
        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.cached_entries, 0);
    }

    #[tokio::test]
    async fn database_backend_default_verify_integrity() {
        let backend = MockBackend;
        assert!(backend.verify_integrity().await.is_ok());
    }

    #[tokio::test]
    async fn default_list_entries_returns_empty() {
        let backend = MockBackend;
        let entries = backend.list_entries(false).await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn default_set_ttl_returns_error() {
        let backend = MockBackend;
        let res = backend.set_ttl(TtlSelector::All, 3600).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("not supported"));

        backend
            .set_ttl(TtlSelector::One("pkg::1.0".into()), 3600)
            .await
            .unwrap_err();
        backend
            .set_ttl(TtlSelector::Multiple(vec!["a".into(), "b".into()]), 3600)
            .await
            .unwrap_err();
    }

    /// Mock IgnoreDb for testing trait consumers (e.g. scan FP filtering).
    #[derive(Default)]
    struct MockIgnoreDb {
        entries: std::sync::RwLock<
            std::collections::HashMap<String, (String, Option<String>)>,
        >,
    }

    impl super::IgnoreDb for MockIgnoreDb {
        fn mark(
            &self,
            cve_id: &str,
            comment: &str,
            project_id: Option<&str>,
        ) -> Result<(), DatabaseError> {
            self.entries.write().unwrap().insert(
                cve_id.to_string(),
                (comment.to_string(), project_id.map(String::from)),
            );
            Ok(())
        }

        fn unmark(&self, cve_id: &str) -> Result<(), DatabaseError> {
            self.entries.write().unwrap().remove(cve_id);
            Ok(())
        }

        fn is_marked(&self, cve_id: &str) -> Result<bool, DatabaseError> {
            Ok(self.entries.read().unwrap().contains_key(cve_id))
        }

        fn marked_ids(
            &self,
            project_id: Option<&str>,
        ) -> Result<std::collections::HashSet<String>, DatabaseError> {
            let guard = self.entries.read().unwrap();
            let set: std::collections::HashSet<String> = guard
                .iter()
                .filter(|(_, (_, pid))| match (pid, project_id) {
                    (None, _) => true,
                    (Some(p), Some(sp)) => p == sp,
                    (Some(_), None) => false,
                })
                .map(|(k, _)| k.clone())
                .collect();
            Ok(set)
        }
    }

    #[test]
    fn ignore_db_trait_marked_ids_global_only_when_no_project() {
        let db = MockIgnoreDb::default();
        db.mark("CVE-A", "a", None).unwrap();
        db.mark("CVE-B", "b", Some("proj1")).unwrap();
        let ids = db.marked_ids(None).unwrap();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains("CVE-A"));
    }

    #[test]
    fn ignore_db_trait_marked_ids_includes_global_and_scoped() {
        let db = MockIgnoreDb::default();
        db.mark("CVE-GLOBAL", "g", None).unwrap();
        db.mark("CVE-PROJ", "p", Some("myproj")).unwrap();
        let ids = db.marked_ids(Some("myproj")).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("CVE-GLOBAL"));
        assert!(ids.contains("CVE-PROJ"));
    }

    #[test]
    fn reject_world_writable_db_missing_file_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.redb");
        assert!(!path.exists());
        assert!(super::reject_world_writable_db(&path).is_ok());
    }

    #[test]
    fn reject_world_writable_db_safe_perms_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("safe.redb");
        std::fs::write(&path, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        assert!(super::reject_world_writable_db(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn reject_world_writable_db_world_writable_err() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worldwritable.redb");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        let res = super::reject_world_writable_db(&path);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("world-writable"));
    }
}
