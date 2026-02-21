// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use vlz_db::DatabaseBackend;

#[derive(thiserror::Error, Debug)]
pub enum IntegrityError {
    /// Backend verify_integrity failed; source chain preserved for verbose mode (NFR-018).
    #[error("Database integrity check failed")]
    Backend(#[from] vlz_db::DatabaseError),

    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait IntegrityChecker: Send + Sync {
    async fn verify(&self, db: &dyn DatabaseBackend) -> Result<(), IntegrityError>;
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
    async fn verify(&self, db: &dyn DatabaseBackend) -> Result<(), IntegrityError> {
        db.verify_integrity()
            .await
            .map_err(IntegrityError::Backend)
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
        async fn verify_integrity(&self) -> Result<(), DatabaseError> {
            Err(DatabaseError::Other("mock integrity failure".to_string()))
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
        assert!(err.source().unwrap().to_string().contains("mock integrity failure"));
    }

    #[tokio::test]
    async fn mock_backend_ok_all_methods() {
        let db = MockBackendOk;
        let pkg = Package {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
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
        };
        db.init().await.unwrap();
        assert!(db.get(&pkg, "osv").await.unwrap().is_none());
        db.put(&pkg, "osv", &[], None).await.unwrap();
        let _ = db.stats().await.unwrap();
        let r = db.verify_integrity().await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("mock integrity failure"));
    }

    #[test]
    fn integrity_error_other_display() {
        let e = IntegrityError::Other("custom message".to_string());
        assert_eq!(e.to_string(), "custom message");
    }

    #[test]
    fn integrity_error_backend_has_source() {
        use vlz_db::DatabaseError;
        let db_err = DatabaseError::Other("mock integrity failure".to_string());
        let e = IntegrityError::Backend(db_err);
        assert!(e.source().is_some());
        assert!(e.source().unwrap().to_string().contains("mock integrity failure"));
    }

    #[test]
    fn backend_delegating_checker_default() {
        let _ = BackendDelegatingChecker::default();
    }
}
