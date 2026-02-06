// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

// This file is part of super-duper. Copyright © 2026 Travis Post
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

// You should have received a copy of the GNU General Public License along with
// super-duper. If not, see <https://www.gnu.org/licenses/>.

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
