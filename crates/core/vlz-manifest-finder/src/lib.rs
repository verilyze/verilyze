// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use std::path::{Path, PathBuf};

#[derive(thiserror::Error, Debug)]
pub enum FinderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid regex: {0}")]
    Regex(String),

    #[error("{0}")]
    Other(String),
}

/// Trait for discovering manifest files on disk.
/// Language plugins implement this to find manifests for their ecosystem.
#[async_trait]
pub trait ManifestFinder: Send + Sync {
    /// Return the language name (e.g. "python", "java") for `vlz list`.
    fn language_name(&self) -> &str;

    /// Return a list of manifest file paths for the given `root`.
    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError>;
}
