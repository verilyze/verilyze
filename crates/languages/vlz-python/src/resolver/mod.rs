// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod ephemeral_venv;
mod lock_discovery;
mod lock_parser;
mod manifest_dir;
mod pip_freeze;
mod pip_lock;
mod pip_venv;
mod pip_version;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use vlz_manifest_parser::{
    DependencyGraph, ResolutionDepth, ResolveContext, ResolveResult, Resolver,
    ResolverError,
};

pub use lock_discovery::find_lock_file;
pub use lock_parser::parse_lock_file;
pub use manifest_dir::{
    PipInstallStrategy, find_manifest_project_dir, pip_install_strategy,
};
pub use pip_freeze::parse_pip_freeze;
use pip_lock::{
    manifest_is_pipfile, manifest_is_requirements_txt, run_pip_lock,
};
use pip_version::pip_supports_lock;

/// FR-022 exit-2 message (exact PRD string, NFR-024).
pub const FR_022_TRANSITIVE_ERROR_MESSAGE: &str = "Unable to detect transitive dependencies. Try installing the package manager or generate a lock file before running vlz.";

/// Direct-only reason when `--offline` is active (FR-022a).
pub const DIRECT_ONLY_REASON_OFFLINE: &str = "offline mode";

/// Direct-only reason when `--benchmark` is active (FR-022a).
pub const DIRECT_ONLY_REASON_BENCHMARK: &str = "benchmark mode";

/// Direct-only reason when executable resolution is disabled (SEC-023).
pub const DIRECT_ONLY_REASON_EXEC_DISABLED: &str =
    "executable dependency resolution is disabled";

/// Direct-only reason when pip is unavailable for local project manifests.
pub const DIRECT_ONLY_REASON_UNAVAILABLE: &str =
    "transitive resolution unavailable";

/// Resolver for Python manifests (FR-022, FR-023, FR-022a, SEC-023).
#[derive(Debug)]
pub struct DirectOnlyResolver {
    pip_lock_cache: Mutex<HashMap<String, Vec<vlz_db::Package>>>,
    venv_cache: Mutex<HashMap<String, Vec<vlz_db::Package>>>,
}

impl Default for DirectOnlyResolver {
    fn default() -> Self {
        Self {
            pip_lock_cache: Mutex::new(HashMap::new()),
            venv_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl DirectOnlyResolver {
    /// Create a new resolver.
    pub fn new() -> Self {
        Self::default()
    }

    fn fr022_transitive_error() -> ResolverError {
        ResolverError::Resolve(FR_022_TRANSITIVE_ERROR_MESSAGE.to_string())
    }

    fn transitive_result(packages: Vec<vlz_db::Package>) -> ResolveResult {
        ResolveResult {
            packages,
            depth: ResolutionDepth::Transitive,
            direct_only_reason: None,
        }
    }

    fn direct_only_result(
        packages: Vec<vlz_db::Package>,
        reason: &'static str,
    ) -> ResolveResult {
        ResolveResult {
            packages,
            depth: ResolutionDepth::DirectOnly,
            direct_only_reason: Some(reason),
        }
    }

    fn skip_pip_reason(ctx: &ResolveContext) -> Option<&'static str> {
        if !ctx.skip_pip_resolution {
            return None;
        }
        if ctx.benchmark_mode {
            Some(DIRECT_ONLY_REASON_BENCHMARK)
        } else {
            Some(DIRECT_ONLY_REASON_OFFLINE)
        }
    }

    fn resolve_lock_file(
        manifest_path: &Path,
    ) -> Option<Vec<vlz_db::Package>> {
        let lock_path = find_lock_file(manifest_path)?;
        let content = std::fs::read_to_string(&lock_path).ok()?;
        let packages = parse_lock_file(lock_path.as_path(), &content).ok()?;
        if packages.is_empty() {
            None
        } else {
            Some(packages)
        }
    }

    fn try_pip_lock_cached(
        &self,
        manifest_path: &Path,
        project_dir: &Path,
        ctx: &ResolveContext,
    ) -> Result<Vec<vlz_db::Package>, ResolverError> {
        let cache_key = manifest_path.to_string_lossy().to_string();
        if let Ok(cache) = self.pip_lock_cache.lock()
            && let Some(cached) = cache.get(&cache_key)
            && !cached.is_empty()
        {
            return Ok(cached.clone());
        }
        let packages = run_pip_lock(manifest_path, project_dir, ctx)?;
        if let Ok(mut cache) = self.pip_lock_cache.lock() {
            cache.insert(cache_key, packages.clone());
        }
        Ok(packages)
    }

    fn try_pip_venv_cached(
        &self,
        manifest_path: &Path,
        project_dir: &Path,
        ctx: &ResolveContext,
    ) -> Result<Vec<vlz_db::Package>, ResolverError> {
        let cache_key = project_dir.to_string_lossy().to_string();
        if let Ok(cache) = self.venv_cache.lock()
            && let Some(cached) = cache.get(&cache_key)
            && !cached.is_empty()
        {
            return Ok(cached.clone());
        }
        let packages =
            pip_venv::run_pip_venv_freeze(manifest_path, project_dir, ctx)?;
        if let Ok(mut cache) = self.venv_cache.lock() {
            cache.insert(cache_key, packages.clone());
        }
        Ok(packages)
    }

    fn direct_only_policy(
        graph: &DependencyGraph,
        manifest_path: &Path,
        ctx: &ResolveContext,
        pip_resolution_attempted: bool,
    ) -> Result<ResolveResult, ResolverError> {
        if graph.packages.is_empty() {
            return Err(Self::fr022_transitive_error());
        }

        let reason = if let Some(r) = Self::skip_pip_reason(ctx) {
            r
        } else if !ctx.allow_dependency_code_execution {
            DIRECT_ONLY_REASON_EXEC_DISABLED
        } else if pip_resolution_attempted
            || manifest_is_requirements_txt(manifest_path)
            || manifest_is_pipfile(manifest_path)
        {
            return Err(Self::fr022_transitive_error());
        } else {
            DIRECT_ONLY_REASON_UNAVAILABLE
        };

        Ok(Self::direct_only_result(graph.packages.clone(), reason))
    }

    fn try_pip_lock_transitive(
        &self,
        manifest_path: &Path,
        project_dir: &Path,
        ctx: &ResolveContext,
    ) -> Option<Vec<vlz_db::Package>> {
        if !pip_supports_lock() || manifest_is_pipfile(manifest_path) {
            return None;
        }
        self.try_pip_lock_cached(manifest_path, project_dir, ctx)
            .ok()
    }

    fn resolve_inner(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        let manifest_path = graph
            .manifest_path
            .as_deref()
            .ok_or_else(Self::fr022_transitive_error)?;

        if let Some(packages) = Self::resolve_lock_file(manifest_path) {
            return Ok(Self::transitive_result(packages));
        }

        let project_dir = find_manifest_project_dir(manifest_path)
            .ok_or_else(Self::fr022_transitive_error)?;

        if ctx.skip_pip_resolution {
            return Self::direct_only_policy(graph, manifest_path, ctx, false);
        }

        if !ctx.allow_dependency_code_execution {
            if manifest_is_requirements_txt(manifest_path) {
                if let Some(packages) = self.try_pip_lock_transitive(
                    manifest_path,
                    &project_dir,
                    ctx,
                ) {
                    return Ok(Self::transitive_result(packages));
                }
                return Err(Self::fr022_transitive_error());
            }
            return Self::direct_only_policy(graph, manifest_path, ctx, false);
        }

        if python_package_manager_available() {
            if let Some(packages) =
                self.try_pip_lock_transitive(manifest_path, &project_dir, ctx)
            {
                return Ok(Self::transitive_result(packages));
            }
            if let Ok(packages) =
                self.try_pip_venv_cached(manifest_path, &project_dir, ctx)
            {
                return Ok(Self::transitive_result(packages));
            }
            return Err(Self::fr022_transitive_error());
        }

        Self::direct_only_policy(graph, manifest_path, ctx, false)
    }
}

/// Returns true if pip or pip3 appears to be on PATH (FR-024).
pub fn python_package_manager_available() -> bool {
    for cmd in ["pip3", "pip"] {
        if std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// OS-specific hint when pip is missing (FR-024).
pub fn python_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: apt-get install python3-pip (Debian/Ubuntu) or dnf install python3-pip (Fedora/RHEL).";
    #[cfg(target_os = "macos")]
    return "Install via: brew install python3.";
    #[cfg(target_os = "windows")]
    return "Install Python from https://www.python.org/ and ensure pip is enabled.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Python and pip for your platform.";
}

#[async_trait]
impl Resolver for DirectOnlyResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        self.resolve_inner(graph, ctx)
    }

    fn package_manager_available(&self) -> bool {
        python_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        python_package_manager_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn package_manager_hint_returns_non_empty() {
        let hint = python_package_manager_hint();
        assert!(!hint.is_empty());
        assert!(
            hint.contains("pip") || hint.contains("Python"),
            "hint should mention pip or Python"
        );
    }

    #[test]
    fn python_package_manager_available_does_not_panic() {
        let _ = python_package_manager_available();
    }

    #[test]
    fn fr022_error_message_is_exact_prd_string() {
        assert_eq!(
            FR_022_TRANSITIVE_ERROR_MESSAGE,
            "Unable to detect transitive dependencies. Try installing the package manager or generate a lock file before running vlz."
        );
    }

    #[tokio::test]
    async fn direct_only_resolver_returns_direct_only_for_setup_py_without_lock()
     {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "myproj".to_string(),
                version: "0.1.0".to_string(),
                ecosystem: Some("PyPI".to_string()),
            }],
            manifest_path: Some(PathBuf::from("/tmp/testproj/setup.py")),
        };
        let resolver = DirectOnlyResolver::new();
        let ctx = ResolveContext::default();
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert_eq!(
            result.direct_only_reason,
            Some(DIRECT_ONLY_REASON_EXEC_DISABLED)
        );
    }

    #[tokio::test]
    async fn direct_only_resolver_offline_warns_and_continues() {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "a".to_string(),
                version: "1".to_string(),
                ecosystem: Some("PyPI".to_string()),
            }],
            manifest_path: Some(PathBuf::from("/tmp/testproj/setup.py")),
        };
        let resolver = DirectOnlyResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert_eq!(
            result.direct_only_reason,
            Some(DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[tokio::test]
    async fn direct_only_resolver_empty_graph_exits_error() {
        let graph = DependencyGraph {
            packages: vec![],
            manifest_path: Some(PathBuf::from(
                "/tmp/testproj/requirements.txt",
            )),
        };
        let resolver = DirectOnlyResolver::new();
        let ctx = ResolveContext::default();
        let err = resolver.resolve(&graph, &ctx).await.unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }
}
