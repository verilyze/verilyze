//! Optional integrity‑checker trait (SHA‑256 is the default).

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
