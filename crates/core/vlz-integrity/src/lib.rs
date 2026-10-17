// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

#[cfg(feature = "sha256")]
mod sha256;

#[cfg(feature = "sha256")]
pub use sha256::{SHA256_SEAL_PREFIX, Sha256Sealer};

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use vlz_db::{DatabaseBackend, DatabaseError, EntrySealer};

/// Label reported by `vlz db verify` for SEC-004 seals.
pub const INTEGRITY_LABEL_SHA256: &str = "SHA-256";
/// Label reported by `vlz db verify` for SEC-005 seals.
pub const INTEGRITY_LABEL_FIPS204: &str = "FIPS-204";

/// Success line for `vlz db verify` (SEC-004, SEC-005).
pub fn integrity_ok_message(label: &str) -> String {
    format!("integrity OK ({label})")
}

/// Sealer for the cache DB at `cache_db_path`, chosen by Cargo feature.
/// `fips204` wins over `sha256` because Cargo features cannot be
/// mutually exclusive (SEC-004, SEC-005). `None` when neither is enabled.
#[allow(unused_variables)]
pub fn active_entry_sealer(
    cache_db_path: &Path,
) -> Option<Arc<dyn EntrySealer>> {
    #[cfg(feature = "sha256")]
    {
        return Some(Arc::new(Sha256Sealer));
    }
    #[allow(unreachable_code)]
    None
}

#[derive(thiserror::Error, Debug)]
pub enum IntegrityError {
    /// Backend verify_integrity failed; source chain preserved for verbose mode (NFR-018).
    #[error("Database integrity check failed")]
    Backend(#[source] DatabaseError),

    /// Seals did not match the stored entries (FR-033: exit 1).
    #[error("Database integrity check failed: {0}")]
    Violation(String),

    #[error("{0}")]
    Other(String),
}

impl From<DatabaseError> for IntegrityError {
    fn from(e: DatabaseError) -> Self {
        match e {
            DatabaseError::IntegrityViolation(msg) => Self::Violation(msg),
            other => Self::Backend(other),
        }
    }
}

#[async_trait]
pub trait IntegrityChecker: Send + Sync {
    async fn verify(
        &self,
        db: &dyn DatabaseBackend,
    ) -> Result<(), IntegrityError>;
}

/// Default checker that delegates to the backend's verify_integrity (e.g. SHA-256 for RedB).
#[derive(Debug, Default)]
pub struct BackendDelegatingChecker;

impl BackendDelegatingChecker {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl IntegrityChecker for BackendDelegatingChecker {
    async fn verify(
        &self,
        db: &dyn DatabaseBackend,
    ) -> Result<(), IntegrityError> {
        db.verify_integrity().await.map_err(IntegrityError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::error::Error;
    use vlz_db::{CveRecord, DatabaseError, DatabaseStats, Package};

    struct MockBackendOk;

    #[async_trait]
    impl DatabaseBackend for MockBackendOk {
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
        async fn verify_integrity(&self) -> Result<(), DatabaseError> {
            Ok(())
        }
    }

    struct MockBackendErr;

    #[async_trait]
    impl DatabaseBackend for MockBackendErr {
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
        async fn verify_integrity(&self) -> Result<(), DatabaseError> {
            Err(DatabaseError::Other("mock integrity failure".to_string()))
        }
    }

    const MOCK_VIOLATION: &str = "1 mismatched";

    struct MockBackendViolation;

    #[async_trait]
    impl DatabaseBackend for MockBackendViolation {
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
        async fn verify_integrity(&self) -> Result<(), DatabaseError> {
            Err(DatabaseError::IntegrityViolation(MOCK_VIOLATION.into()))
        }
    }

    #[tokio::test]
    async fn backend_delegating_checker_ok() {
        let checker = BackendDelegatingChecker::new();
        let db = MockBackendOk;
        assert!(checker.verify(&db).await.is_ok());
    }

    #[tokio::test]
    async fn backend_delegating_checker_propagates_error() {
        let checker = BackendDelegatingChecker::new();
        let db = MockBackendErr;
        let r = checker.verify(&db).await;
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(err.to_string().contains("integrity"));
        assert!(
            err.source()
                .unwrap()
                .to_string()
                .contains("mock integrity failure")
        );
    }

    #[tokio::test]
    async fn backend_delegating_checker_shows_violation_detail() {
        let err = BackendDelegatingChecker::new()
            .verify(&MockBackendViolation)
            .await
            .unwrap_err();
        assert!(matches!(err, IntegrityError::Violation(_)));
        assert_eq!(
            err.to_string(),
            format!("Database integrity check failed: {MOCK_VIOLATION}")
        );
    }

    #[test]
    fn integrity_ok_message_names_algorithm() {
        assert_eq!(
            integrity_ok_message(INTEGRITY_LABEL_SHA256),
            "integrity OK (SHA-256)"
        );
        assert_eq!(
            integrity_ok_message(INTEGRITY_LABEL_FIPS204),
            "integrity OK (FIPS-204)"
        );
    }

    #[test]
    fn active_entry_sealer_matches_enabled_feature() {
        let dir = std::path::Path::new("unused-cache-dir");
        let label =
            active_entry_sealer(&dir.join("c.redb")).map(|s| s.label());
        if cfg!(feature = "sha256") {
            assert_eq!(label, Some(INTEGRITY_LABEL_SHA256));
        } else {
            assert_eq!(label, None);
        }
    }

    #[tokio::test]
    async fn mock_backend_ok_all_methods() {
        let db = MockBackendOk;
        let pkg = Package {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        db.init().await.unwrap();
        assert!(db.get(&pkg, "osv").await.unwrap().is_none());
        db.put(&pkg, "osv", &[], None).await.unwrap();
        let _ = db.stats().await.unwrap();
        db.verify_integrity().await.unwrap();
    }

    #[tokio::test]
    async fn mock_backend_err_all_methods() {
        let db = MockBackendErr;
        let pkg = Package {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        db.init().await.unwrap();
        assert!(db.get(&pkg, "osv").await.unwrap().is_none());
        db.put(&pkg, "osv", &[], None).await.unwrap();
        let _ = db.stats().await.unwrap();
        let r = db.verify_integrity().await;
        assert!(r.is_err());
        assert!(
            r.unwrap_err()
                .to_string()
                .contains("mock integrity failure")
        );
    }

    #[tokio::test]
    async fn mock_backend_violation_all_methods() {
        let db = MockBackendViolation;
        let pkg = Package::default();
        db.init().await.unwrap();
        assert!(db.get(&pkg, "osv").await.unwrap().is_none());
        db.put(&pkg, "osv", &[], None).await.unwrap();
        let _ = db.stats().await.unwrap();
    }

    #[test]
    fn integrity_error_other_display() {
        let e = IntegrityError::Other("custom message".to_string());
        assert_eq!(e.to_string(), "custom message");
    }

    #[test]
    fn integrity_error_backend_has_source() {
        use vlz_db::DatabaseError;
        let db_err =
            DatabaseError::Other("mock integrity failure".to_string());
        let e = IntegrityError::Backend(db_err);
        assert!(e.source().is_some());
        assert!(
            e.source()
                .unwrap()
                .to_string()
                .contains("mock integrity failure")
        );
    }

    #[test]
    fn backend_delegating_checker_default() {
        let _ = BackendDelegatingChecker;
    }
}
