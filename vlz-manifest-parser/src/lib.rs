// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum ParserError {
    #[error("Parse error: {0}")]
    Parse(String),

    /// IO error when reading manifest; source preserved for verbose mode (NFR-018).
    #[error("IO error reading manifest")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

#[derive(thiserror::Error, Debug)]
pub enum ResolverError {
    #[error("Resolve error: {0}")]
    Resolve(String),

    /// IO or subprocess error during resolution; source preserved (NFR-018).
    #[error("IO error during resolution")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

/// Very small representation of a dependency graph – enough for the
/// skeleton.  Real implementation will likely use petgraph or a custom
/// DAG structure.
#[derive(Debug, Default, Clone)]
pub struct DependencyGraph {
    pub packages: Vec<vlz_db::Package>,

    /// Path to the manifest file; used by Resolver for lock file discovery (FR-022).
    pub manifest_path: Option<PathBuf>,
}

/// Trait for parsing a manifest file into a dependency graph.
#[async_trait]
pub trait Parser: Send + Sync {
    /// Parse a single manifest file.
    async fn parse(&self, manifest: &PathBuf) -> Result<DependencyGraph, ParserError>;
}

/// Resolves a dependency graph to a full list of packages (e.g. transitive deps).
/// Language plugins may use lock files or package managers to resolve transitive deps (FR-022).
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve the dependency graph to a flat list of packages.
    async fn resolve(
        &self,
        graph: &DependencyGraph,
    ) -> Result<Vec<vlz_db::Package>, ResolverError>;

    /// Whether the package manager for this language is available on PATH (FR-024).
    /// When `--package-manager-required` is set, the scan exits with code 3 if this returns false.
    fn package_manager_available(&self) -> bool;

    /// OS-specific hint when the package manager is missing (FR-024).
    fn package_manager_hint(&self) -> &'static str;
}
