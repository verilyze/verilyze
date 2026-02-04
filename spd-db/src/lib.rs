//! DatabaseBackend trait – the abstraction used by the core binary.
#![deny(unsafe_code)]

use async_trait::async_trait;
//use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    // additional fields (ecosystem, source url…) can be added later
}

/// CVSS version used for the primary score (FR-034).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CvssVersion {
    V2,
    V3,
    V4,
}

/// Severity label for display in reports (FR-013). Derived from primary CVSS score + configurable thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
}

/// Errors that can bubble up from any backend implementation.
#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    /// Initialise the backend (create files, run migrations, …).
    async fn init(&self) -> Result<(), DatabaseError>;

    /// Retrieve all cached CVE records for a package, if present.
    async fn get(&self, pkg: &Package) -> Result<Option<Vec<CveRecord>>, DatabaseError>;

    /// Store freshly‑fetched raw CVE vuln JSON for a package (replaces any existing entry for that package).
    async fn put(&self, pkg: &Package, raw_vulns: &[serde_json::Value]) -> Result<(), DatabaseError>;

    /// Return simple statistics (used by `spd db stats`).
    async fn stats(&self) -> Result<DatabaseStats, DatabaseError>;

    /// Verify integrity of the underlying storage.
    ///
    /// The default implementation simply returns `Ok(())`.  Concrete
    /// back‑ends may override it (e.g. SHA‑256, FIPS‑204).
    async fn verify_integrity(&self) -> Result<(), DatabaseError> {
        Ok(())
    }
}
