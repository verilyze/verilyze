// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod ephemeral_venv;
mod lock_discovery;
mod lock_parser;
mod manifest_cache_key;
mod manifest_dir;
mod pip_freeze;
mod pip_lock;
mod pip_venv;
mod pip_version;

#[cfg(test)]
mod test_fixtures;

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
pub use manifest_cache_key::manifest_cache_key;
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

/// Direct-only reason when `allow_direct_only_fallback` is enabled (FR-022a).
pub const DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE: &str =
    "transitive resolution failed; direct-only fallback enabled";

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

    fn fr022_transitive_error_with_cause(
        cause: ResolverError,
    ) -> ResolverError {
        ResolverError::ResolveWithCause {
            message: FR_022_TRANSITIVE_ERROR_MESSAGE.to_string(),
            cause: Box::new(cause),
        }
    }

    fn require_transitive_or_fallback(
        graph: &DependencyGraph,
        ctx: &ResolveContext,
        cause: Option<ResolverError>,
    ) -> Result<ResolveResult, ResolverError> {
        if ctx.allow_direct_only_fallback && !graph.packages.is_empty() {
            Ok(Self::direct_only_result(
                graph.packages.clone(),
                DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE,
            ))
        } else if let Some(cause) = cause {
            Err(Self::fr022_transitive_error_with_cause(cause))
        } else {
            Err(Self::fr022_transitive_error())
        }
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

    async fn try_pip_lock_cached(
        &self,
        manifest_path: &Path,
        project_dir: &Path,
        ctx: &ResolveContext,
    ) -> Result<Vec<vlz_db::Package>, ResolverError> {
        let content =
            tokio::fs::read_to_string(manifest_path)
                .await
                .map_err(|e| {
                    ResolverError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "reading {} for resolution cache: {e}",
                            manifest_path.display()
                        ),
                    ))
                })?;
        let cache_key = manifest_cache_key(&content, ctx);
        if let Ok(cache) = self.pip_lock_cache.lock()
            && let Some(cached) = cache.get(&cache_key)
            && !cached.is_empty()
        {
            return Ok(cached.clone());
        }
        let manifest_path = manifest_path.to_path_buf();
        let project_dir = project_dir.to_path_buf();
        let ctx = ctx.clone();
        let packages = tokio::task::spawn_blocking(move || {
            run_pip_lock(&manifest_path, &project_dir, &ctx)
        })
        .await
        .map_err(|e| {
            ResolverError::Resolve(format!("pip lock task failed: {e}"))
        })??;
        if let Ok(mut cache) = self.pip_lock_cache.lock() {
            cache.insert(cache_key, packages.clone());
        }
        Ok(packages)
    }

    async fn try_pip_venv_cached(
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
        let manifest_path = manifest_path.to_path_buf();
        let project_dir = project_dir.to_path_buf();
        let ctx = ctx.clone();
        let packages = tokio::task::spawn_blocking(move || {
            pip_venv::run_pip_venv_freeze(&manifest_path, &project_dir, &ctx)
        })
        .await
        .map_err(|e| {
            ResolverError::Resolve(format!("pip venv task failed: {e}"))
        })??;
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
            return Self::require_transitive_or_fallback(graph, ctx, None);
        } else {
            DIRECT_ONLY_REASON_UNAVAILABLE
        };

        Ok(Self::direct_only_result(graph.packages.clone(), reason))
    }

    /// `Ok(Some(_))` on success, `Ok(None)` when pip lock does not apply,
    /// `Err(_)` when pip lock was attempted and failed.
    async fn try_pip_lock_transitive(
        &self,
        manifest_path: &Path,
        project_dir: &Path,
        ctx: &ResolveContext,
    ) -> Result<Option<Vec<vlz_db::Package>>, ResolverError> {
        if !pip_supports_lock() || manifest_is_pipfile(manifest_path) {
            return Ok(None);
        }
        match self
            .try_pip_lock_cached(manifest_path, project_dir, ctx)
            .await
        {
            Ok(packages) => Ok(Some(packages)),
            Err(err) => Err(err),
        }
    }

    async fn resolve_inner(
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
                return match self
                    .try_pip_lock_transitive(manifest_path, &project_dir, ctx)
                    .await
                {
                    Ok(Some(packages)) => {
                        Ok(Self::transitive_result(packages))
                    }
                    Ok(None) => {
                        Self::require_transitive_or_fallback(graph, ctx, None)
                    }
                    Err(pip_err) => Self::require_transitive_or_fallback(
                        graph,
                        ctx,
                        Some(pip_err),
                    ),
                };
            }
            return Self::direct_only_policy(graph, manifest_path, ctx, false);
        }

        if python_package_manager_available() {
            let pip_lock_err = match self
                .try_pip_lock_transitive(manifest_path, &project_dir, ctx)
                .await
            {
                Ok(Some(packages)) => {
                    return Ok(Self::transitive_result(packages));
                }
                Ok(None) => None,
                Err(err) => Some(err),
            };
            return match self
                .try_pip_venv_cached(manifest_path, &project_dir, ctx)
                .await
            {
                Ok(packages) => Ok(Self::transitive_result(packages)),
                Err(venv_err) => {
                    let venv_msg = venv_err.to_string();
                    let cause = pip_lock_err.map_or(venv_err, |pip_err| {
                        ResolverError::ResolveWithCause {
                            message: venv_msg,
                            cause: Box::new(pip_err),
                        }
                    });
                    Self::require_transitive_or_fallback(
                        graph,
                        ctx,
                        Some(cause),
                    )
                }
            };
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
        self.resolve_inner(graph, ctx).await
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

    use crate::resolver::test_fixtures::{
        empty_path, fake_pip_lock_counting, fake_pip_lock_failure,
        fake_pip_lock_success, fake_python_venv,
    };

    fn error_chain_messages(err: &dyn std::error::Error) -> Vec<String> {
        let mut chain = vec![err.to_string()];
        let mut next = err.source();
        while let Some(cause) = next {
            chain.push(cause.to_string());
            next = cause.source();
        }
        chain
    }

    fn sample_graph(manifest: PathBuf) -> DependencyGraph {
        DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                ecosystem: Some("PyPI".to_string()),
            }],
            manifest_path: Some(manifest),
        }
    }

    fn block_on_resolver_test<F>(future: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future);
    }

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
    fn resolver_trait_package_manager_methods() {
        let resolver = DirectOnlyResolver::new();
        let _ = resolver.package_manager_available();
        assert!(!resolver.package_manager_hint().is_empty());
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
    async fn direct_only_resolver_benchmark_mode_reason() {
        let graph = sample_graph(PathBuf::from("/tmp/testproj/setup.py"));
        let resolver = DirectOnlyResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: true,
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert_eq!(
            result.direct_only_reason,
            Some(DIRECT_ONLY_REASON_BENCHMARK)
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

    #[tokio::test]
    async fn direct_only_resolver_missing_manifest_path_errors() {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "a".to_string(),
                version: "1".to_string(),
                ecosystem: Some("PyPI".to_string()),
            }],
            manifest_path: None,
        };
        let resolver = DirectOnlyResolver::new();
        let err = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }

    #[tokio::test]
    async fn direct_only_resolver_uses_adjacent_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        let pylock = dir.path().join("pylock.toml");
        std::fs::write(&req, b"requests>=2.0\n").unwrap();
        std::fs::write(
            &pylock,
            "[[packages]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
        )
        .unwrap();
        let graph = sample_graph(req);
        let resolver = DirectOnlyResolver::new();
        let result = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert!(result.packages.iter().any(|p| p.name == "requests"));
    }

    #[tokio::test]
    async fn direct_only_resolver_ignores_empty_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let setup = dir.path().join("setup.py");
        let pylock = dir.path().join("pylock.toml");
        std::fs::write(&setup, b"from setuptools import setup\nsetup()\n")
            .unwrap();
        std::fs::write(&pylock, b"packages = []\n").unwrap();
        let graph = sample_graph(setup);
        let resolver = DirectOnlyResolver::new();
        let result = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_requirements_pip_lock_failure_surfaces_cause() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests>=2.0\n").unwrap();
        let graph = sample_graph(req);
        let fake = fake_pip_lock_failure();
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let err = resolver
                    .resolve(&graph, &ResolveContext::default())
                    .await
                    .unwrap_err();
                let chain = error_chain_messages(&err);
                assert!(
                    chain[0].contains(FR_022_TRANSITIVE_ERROR_MESSAGE),
                    "outer: {chain:?}"
                );
                assert!(
                    chain.iter().any(|m| m.contains("pip lock failed for")),
                    "resolver chain: {chain:?}"
                );
                let anyhow_err: anyhow::Error = err.into();
                let anyhow_chain: Vec<String> = anyhow_err
                    .chain()
                    .map(std::string::ToString::to_string)
                    .collect();
                assert!(
                    anyhow_chain.iter().any(|m| m.contains("pip lock failed")),
                    "anyhow chain: {anyhow_chain:?}"
                );
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_requirements_pip_lock_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests>=2.0\n").unwrap();
        let graph = sample_graph(req);
        let fake = fake_pip_lock_success(
            "[[packages]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
        );
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let result = resolver
                    .resolve(&graph, &ResolveContext::default())
                    .await
                    .unwrap();
                assert_eq!(result.depth, ResolutionDepth::Transitive);
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_pip_lock_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests>=2.0\n").unwrap();
        let graph = sample_graph(req);
        let fake = fake_pip_lock_success(
            "[[packages]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
        );
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext::default();
                let first = resolver.resolve(&graph, &ctx).await.unwrap();
                let second = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(first.depth, ResolutionDepth::Transitive);
                assert_eq!(second.packages, first.packages);
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_pip_lock_content_hash_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let req_a = dir.path().join("a").join("requirements.txt");
        let req_b = dir.path().join("b").join("requirements.txt");
        std::fs::create_dir_all(req_a.parent().unwrap()).unwrap();
        std::fs::create_dir_all(req_b.parent().unwrap()).unwrap();
        let content = b"requests>=2.0\n";
        std::fs::write(&req_a, content).unwrap();
        std::fs::write(&req_b, content).unwrap();
        let counter = dir.path().join("pip_lock_count");
        let pylock =
            "[[packages]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let fake = fake_pip_lock_counting(pylock, &counter);
        let graph_a = sample_graph(req_a);
        let graph_b = sample_graph(req_b);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext::default();
                let first = resolver.resolve(&graph_a, &ctx).await.unwrap();
                let second = resolver.resolve(&graph_b, &ctx).await.unwrap();
                assert_eq!(first.depth, ResolutionDepth::Transitive);
                assert_eq!(second.depth, ResolutionDepth::Transitive);
                assert_eq!(second.packages, first.packages);
                let count = std::fs::read_to_string(&counter)
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(0);
                assert_eq!(
                    count, 1,
                    "identical manifests should share one pip lock"
                );
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_exec_enabled_venv_fallback() {
        let fake = fake_python_venv(0, "requests==2.31.0", 0, 0);
        let project = fake.project_dir();
        let setup = project.join("setup.py");
        std::fs::write(
            &setup,
            b"from setuptools import setup\nsetup(name='x', install_requires=['requests'])\n",
        )
        .unwrap();
        let graph = sample_graph(setup);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_dependency_code_execution: true,
                    ..Default::default()
                };
                let result = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(result.depth, ResolutionDepth::Transitive);
                assert!(result.packages.iter().any(|p| p.name == "requests"));
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_exec_enabled_venv_cache_hit() {
        let fake = fake_python_venv(0, "requests==2.31.0", 0, 0);
        let project = fake.project_dir();
        let setup = project.join("setup.py");
        std::fs::write(
            &setup,
            b"from setuptools import setup\nsetup(name='x', install_requires=['requests'])\n",
        )
        .unwrap();
        let graph = sample_graph(setup);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_dependency_code_execution: true,
                    ..Default::default()
                };
                let first = resolver.resolve(&graph, &ctx).await.unwrap();
                let second = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(second.packages, first.packages);
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_exec_enabled_pip_unavailable_direct_only() {
        let fake = empty_path();
        let project = fake.project_dir();
        let setup = project.join("setup.py");
        std::fs::write(&setup, b"from setuptools import setup\nsetup()\n")
            .unwrap();
        let graph = sample_graph(setup);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_dependency_code_execution: true,
                    ..Default::default()
                };
                let result = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(result.depth, ResolutionDepth::DirectOnly);
                assert_eq!(
                    result.direct_only_reason,
                    Some(DIRECT_ONLY_REASON_UNAVAILABLE)
                );
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_pipfile_with_exec_errors_fr022() {
        let fake = fake_python_venv(1, "requests==2.31.0", 0, 0);
        let project = fake.project_dir();
        let pipfile = project.join("Pipfile");
        std::fs::write(&pipfile, b"[[source]]\nurl = \"pypi\"\n").unwrap();
        let graph = sample_graph(pipfile);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_dependency_code_execution: true,
                    ..Default::default()
                };
                let err = resolver.resolve(&graph, &ctx).await.unwrap_err();
                assert!(
                    err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE)
                );
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_requirements_pip_lock_failure_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests>=2.0\n").unwrap();
        let graph = sample_graph(req);
        let fake = fake_pip_lock_failure();
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_direct_only_fallback: true,
                    ..Default::default()
                };
                let result = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(result.depth, ResolutionDepth::DirectOnly);
                assert_eq!(
                    result.direct_only_reason,
                    Some(DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE)
                );
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_pipfile_with_exec_fallback() {
        let fake = fake_python_venv(1, "requests==2.31.0", 0, 0);
        let project = fake.project_dir();
        let pipfile = project.join("Pipfile");
        std::fs::write(&pipfile, b"[[source]]\nurl = \"pypi\"\n").unwrap();
        let graph = sample_graph(pipfile);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_dependency_code_execution: true,
                    allow_direct_only_fallback: true,
                    ..Default::default()
                };
                let result = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(result.depth, ResolutionDepth::DirectOnly);
                assert_eq!(
                    result.direct_only_reason,
                    Some(DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE)
                );
            });
        });
    }

    #[cfg(unix)]
    #[test]
    fn direct_only_resolver_exec_enabled_venv_failure_fallback() {
        let fake = fake_python_venv(1, "requests==2.31.0", 0, 0);
        let project = fake.project_dir();
        let setup = project.join("setup.py");
        std::fs::write(
            &setup,
            b"from setuptools import setup\nsetup(name='x', install_requires=['requests'])\n",
        )
        .unwrap();
        let graph = sample_graph(setup);
        fake.with_path(|| {
            block_on_resolver_test(async {
                let resolver = DirectOnlyResolver::new();
                let ctx = ResolveContext {
                    allow_dependency_code_execution: true,
                    allow_direct_only_fallback: true,
                    ..Default::default()
                };
                let result = resolver.resolve(&graph, &ctx).await.unwrap();
                assert_eq!(result.depth, ResolutionDepth::DirectOnly);
                assert_eq!(
                    result.direct_only_reason,
                    Some(DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE)
                );
            });
        });
    }

    #[tokio::test]
    async fn direct_only_resolver_empty_graph_stays_error_with_fallback() {
        let graph = DependencyGraph {
            packages: vec![],
            manifest_path: Some(PathBuf::from(
                "/tmp/testproj/requirements.txt",
            )),
        };
        let resolver = DirectOnlyResolver::new();
        let ctx = ResolveContext {
            allow_direct_only_fallback: true,
            ..Default::default()
        };
        let err = resolver.resolve(&graph, &ctx).await.unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }
}
