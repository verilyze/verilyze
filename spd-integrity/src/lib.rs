//! Optional integrity‑checker trait (SHA‑256 is the default).
#![deny(unsafe_code)]

use async_trait::async_trait;
use spd_db::DatabaseBackend;

#[derive(thiserror::Error, Debug)]
pub enum IntegrityError {
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
            .map_err(|e| IntegrityError::Other(e.to_string()))
    }
}
