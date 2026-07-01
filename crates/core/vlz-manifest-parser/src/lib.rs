// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use std::path::{Path, PathBuf};

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

/// Scan-time context passed to resolvers (FR-022, FR-023, SEC-023).
#[derive(Debug, Clone, Default)]
pub struct ResolveContext {
    /// Do not remove ephemeral venv after the scan (FR-023 debug).
    pub keep_ephemeral_venv: bool,
    /// Skip pip resolution entirely (`--offline` or `--benchmark` mode).
    pub skip_pip_resolution: bool,
    /// True when `--benchmark` is active (for FR-022a warning reason text).
    pub benchmark_mode: bool,
    /// Allow pip operations that may execute local project or dependency build code.
    /// Secure default: false (SEC-023).
    pub allow_dependency_code_execution: bool,
}

/// Whether resolution produced a full transitive tree or direct deps only (FR-022a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionDepth {
    Transitive,
    DirectOnly,
}

/// Result of dependency resolution including depth metadata for FR-022a warnings.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub packages: Vec<vlz_db::Package>,
    pub depth: ResolutionDepth,
    /// Set when `depth == DirectOnly` (e.g. `"offline mode"`).
    pub direct_only_reason: Option<&'static str>,
}

/// Shown after the manifest path and reason in FR-022a direct-only warnings (NFR-024).
pub const DIRECT_ONLY_WARNING_REMEDIATION: &str =
    "Add an adjacent lock file for transitive coverage.";

/// Documentation pointer appended to every direct-only warning (NFR-024).
pub const DIRECT_ONLY_WARNING_DOC_HINT: &str = "See `man vlz` or docs/FAQ.md.";

/// Format an FR-022a direct-only warning for stderr (OP-018).
pub fn format_direct_only_warning(
    manifest_display: &str,
    reason: &str,
) -> String {
    format!(
        "vlz warning: Only direct dependencies were scanned for {manifest_display} ({reason}). {DIRECT_ONLY_WARNING_REMEDIATION} {DIRECT_ONLY_WARNING_DOC_HINT}"
    )
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
    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError>;
}

/// Resolves a dependency graph to a full list of packages (e.g. transitive deps).
/// Language plugins may use lock files or package managers to resolve transitive deps (FR-022).
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve the dependency graph to a flat list of packages.
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError>;

    /// Whether the package manager for this language is available on PATH (FR-024).
    /// When `--package-manager-required` is set, the scan exits with code 3 if this returns false.
    fn package_manager_available(&self) -> bool;

    /// OS-specific hint when the package manager is missing (FR-024).
    fn package_manager_hint(&self) -> &'static str;
}
