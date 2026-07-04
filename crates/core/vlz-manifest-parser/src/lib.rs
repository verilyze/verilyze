// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use std::collections::HashMap;
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

    /// Transitive resolution failed after a nested resolver step (NFR-018).
    #[error("Resolve error: {message}")]
    ResolveWithCause {
        message: String,
        #[source]
        cause: Box<ResolverError>,
    },

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
    /// When true, FR-022 transitive-resolution failures fall back to direct-only
    /// scan with FR-022a warning instead of exit 2 (FR-022, FR-022a).
    pub allow_direct_only_fallback: bool,
    /// When non-empty, only discover/merge listed Python lock file basenames.
    pub python_lock_files: Vec<String>,
}

/// Whether resolution produced a full transitive tree or direct deps only (FR-022a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResolutionDepth {
    #[default]
    Transitive,
    DirectOnly,
}

/// Result of dependency resolution including depth metadata for FR-022a warnings.
#[derive(Debug, Clone, Default)]
pub struct ResolveResult {
    pub packages: Vec<vlz_db::Package>,
    pub depth: ResolutionDepth,
    /// Set when `depth == DirectOnly` (e.g. `"offline mode"`).
    pub direct_only_reason: Option<&'static str>,
    /// When non-empty, FR-036 attribution uses these paths per package instead of
    /// the discovered entry point path (e.g. adjacent lock file sources).
    pub package_source_paths: HashMap<vlz_db::Package, Vec<PathBuf>>,
    /// Lock files merged during adjacent resolution; used for multi-lock warnings.
    pub resolved_lock_paths: Vec<PathBuf>,
}

/// Shown after the manifest path and reason in FR-022a direct-only warnings (NFR-024).
pub const DIRECT_ONLY_WARNING_REMEDIATION: &str =
    "Add an adjacent lock file for transitive coverage.";

/// Documentation pointer appended to every direct-only warning (NFR-024).
pub const DIRECT_ONLY_WARNING_DOC_HINT: &str = "See `man vlz` or docs/FAQ.md.";

/// Direct-only reason when `--offline` is active (FR-022a).
pub const DIRECT_ONLY_REASON_OFFLINE: &str = "offline mode";

/// Direct-only reason when `--benchmark` is active (FR-022a).
pub const DIRECT_ONLY_REASON_BENCHMARK: &str = "benchmark mode";

/// Direct-only reason when transitive resolution could not be performed.
pub const DIRECT_ONLY_REASON_UNAVAILABLE: &str =
    "transitive resolution unavailable";

/// FR-022 exit-2 message (exact PRD string, NFR-024).
pub const FR_022_TRANSITIVE_ERROR_MESSAGE: &str = "Unable to detect transitive dependencies. Try installing the package manager or generate a lock file before running vlz.";

/// Direct-only reason when `allow_direct_only_fallback` is enabled (FR-022a).
pub const DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE: &str =
    "transitive resolution failed; direct-only fallback enabled";

/// Build FR-022 resolver error for mandatory transitive resolution failure.
pub fn fr022_transitive_error() -> ResolverError {
    ResolverError::Resolve(FR_022_TRANSITIVE_ERROR_MESSAGE.to_string())
}

/// FR-022 error with nested cause for verbose diagnostics (NFR-018).
pub fn fr022_transitive_error_with_cause(
    cause: ResolverError,
) -> ResolverError {
    ResolverError::ResolveWithCause {
        message: FR_022_TRANSITIVE_ERROR_MESSAGE.to_string(),
        cause: Box::new(cause),
    }
}

/// Exit 2 unless `allow_direct_only_fallback` permits direct-only scan (FR-022, FR-022a).
pub fn require_transitive_or_fallback(
    graph: &DependencyGraph,
    ctx: &ResolveContext,
    cause: Option<ResolverError>,
) -> Result<ResolveResult, ResolverError> {
    if ctx.allow_direct_only_fallback && !graph.packages.is_empty() {
        Ok(direct_only_result(
            graph.packages.clone(),
            DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE,
        ))
    } else if let Some(cause) = cause {
        Err(fr022_transitive_error_with_cause(cause))
    } else {
        Err(fr022_transitive_error())
    }
}

/// FR-022a reason when `--offline` or `--benchmark` skips package-manager resolution.
pub fn skip_package_manager_reason(
    ctx: &ResolveContext,
) -> Option<&'static str> {
    if !ctx.skip_pip_resolution {
        return None;
    }
    if ctx.benchmark_mode {
        Some(DIRECT_ONLY_REASON_BENCHMARK)
    } else {
        Some(DIRECT_ONLY_REASON_OFFLINE)
    }
}

/// Build a direct-only `ResolveResult` with FR-022a metadata.
pub fn direct_only_result(
    packages: Vec<vlz_db::Package>,
    reason: &'static str,
) -> ResolveResult {
    ResolveResult {
        packages,
        depth: ResolutionDepth::DirectOnly,
        direct_only_reason: Some(reason),
        ..Default::default()
    }
}

/// Format an FR-022a direct-only warning for stderr (OP-018).
pub fn format_direct_only_warning(
    manifest_display: &str,
    reason: &str,
) -> String {
    format!(
        "vlz warning: Only direct dependencies were scanned for {manifest_display} ({reason}). {DIRECT_ONLY_WARNING_REMEDIATION} {DIRECT_ONLY_WARNING_DOC_HINT}"
    )
}

/// Multi-lock diagnostic warning (not FR-022a direct-only).
pub fn format_multi_lock_warning(
    dir_display: &str,
    lock_names: &[String],
) -> String {
    format!(
        "vlz warning: Multiple lock files in {dir_display} were scanned and packages merged: {}. Keep one canonical lock file for clarity. {DIRECT_ONLY_WARNING_DOC_HINT}",
        lock_names.join(", ")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_package_manager_reason_offline() {
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: false,
            ..Default::default()
        };
        assert_eq!(
            skip_package_manager_reason(&ctx),
            Some(DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[test]
    fn skip_package_manager_reason_benchmark() {
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: true,
            ..Default::default()
        };
        assert_eq!(
            skip_package_manager_reason(&ctx),
            Some(DIRECT_ONLY_REASON_BENCHMARK)
        );
    }

    #[test]
    fn skip_package_manager_reason_normal_scan() {
        let ctx = ResolveContext::default();
        assert_eq!(skip_package_manager_reason(&ctx), None);
    }

    #[test]
    fn direct_only_result_sets_depth_and_reason() {
        let packages = vec![vlz_db::Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            ecosystem: None,
        }];
        let result =
            direct_only_result(packages.clone(), DIRECT_ONLY_REASON_OFFLINE);
        assert_eq!(result.packages, packages);
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert_eq!(
            result.direct_only_reason,
            Some(DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    fn sample_graph() -> DependencyGraph {
        DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "foo".to_string(),
                version: "1.0".to_string(),
                ecosystem: None,
            }],
            manifest_path: None,
        }
    }

    #[test]
    fn require_transitive_or_fallback_exits_fr022() {
        let graph = sample_graph();
        let ctx = ResolveContext::default();
        let err =
            require_transitive_or_fallback(&graph, &ctx, None).unwrap_err();
        assert!(
            err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE),
            "got: {err}"
        );
    }

    #[test]
    fn require_transitive_or_fallback_with_cause_chains() {
        let graph = sample_graph();
        let ctx = ResolveContext::default();
        let inner = ResolverError::Resolve("cargo failed".to_string());
        let err = require_transitive_or_fallback(&graph, &ctx, Some(inner))
            .unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }

    #[test]
    fn require_transitive_or_fallback_allows_direct_only_when_flag_set() {
        let graph = sample_graph();
        let ctx = ResolveContext {
            allow_direct_only_fallback: true,
            ..Default::default()
        };
        let result =
            require_transitive_or_fallback(&graph, &ctx, None).unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert_eq!(
            result.direct_only_reason,
            Some(DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE)
        );
    }

    #[test]
    fn require_transitive_or_fallback_empty_graph_still_exits_fr022() {
        let graph = DependencyGraph::default();
        let ctx = ResolveContext {
            allow_direct_only_fallback: true,
            ..Default::default()
        };
        let err =
            require_transitive_or_fallback(&graph, &ctx, None).unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }
}
