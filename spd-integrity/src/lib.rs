// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use spd_db::{CveRecord, DatabaseError, DatabaseStats, Package};

    struct MockBackendOk;

    #[async_trait]
    impl DatabaseBackend for MockBackendOk {
        async fn init(&self) -> Result<(), DatabaseError> {
            Ok(())
        }
        async fn get(&self, _: &Package) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
            Ok(None)
        }
        async fn put(
            &self,
            _: &Package,
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
        async fn get(&self, _: &Package) -> Result<Option<Vec<CveRecord>>, DatabaseError> {
            Ok(None)
        }
        async fn put(
            &self,
            _: &Package,
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
        assert!(r.unwrap_err().to_string().contains("mock integrity failure"));
    }
}
