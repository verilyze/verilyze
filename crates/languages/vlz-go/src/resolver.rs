// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use vlz_manifest_parser::{
    DependencyGraph, ResolutionDepth, ResolveContext, ResolveResult, Resolver,
    ResolverError, direct_only_result, fr022_transitive_error,
    require_transitive_or_fallback, skip_package_manager_reason,
};

use crate::parser::GO_ECOSYSTEM;

/// Get the directory containing go.mod (manifest parent).
pub fn find_go_mod_dir(manifest_path: &Path) -> Option<std::path::PathBuf> {
    manifest_path.parent().map(|p| p.to_path_buf())
}

/// Parse `go list -m all` output into a list of packages.
/// Output format: one line per module, "modulepath version".
/// Public for fuzzing.
pub fn parse_go_list_m_all(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ResolverError> {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            packages.push(vlz_db::Package {
                name: parts[0].to_string(),
                version: parts[1].to_string(),
                ecosystem: Some(GO_ECOSYSTEM.to_string()),
            });
        }
    }
    Ok(packages)
}

/// Resolver that prefers `go list -m all`, falls back to graph from parser.
/// Caches output when multiple go.mod share the same directory.
#[derive(Debug)]
pub struct GoResolver {
    list_cache: Mutex<HashMap<String, Vec<vlz_db::Package>>>,
}

impl Default for GoResolver {
    fn default() -> Self {
        Self {
            list_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl GoResolver {
    /// Create a new Go resolver.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Returns true if go appears to be on PATH (FR-024).
pub fn go_package_manager_available() -> bool {
    std::process::Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// OS-specific hint when go is missing (FR-024).
pub fn go_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: apt-get install golang-go (Debian/Ubuntu) or dnf install golang (Fedora).";
    #[cfg(target_os = "macos")]
    return "Install via: brew install go.";
    #[cfg(target_os = "windows")]
    return "Install Go from https://go.dev/dl/ and ensure go is on PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Go for your platform (https://go.dev/dl/).";
}

#[async_trait]
impl Resolver for GoResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        if let Some(reason) = skip_package_manager_reason(ctx) {
            return Ok(direct_only_result(graph.packages.clone(), reason));
        }

        if let Some(ref manifest_path) = graph.manifest_path {
            let dir = find_go_mod_dir(manifest_path);
            if let Some(ref work_dir) = dir {
                let cache_key = work_dir.to_string_lossy().to_string();
                if let Ok(cache) = self.list_cache.lock()
                    && let Some(cached) = cache.get(&cache_key)
                {
                    return Ok(ResolveResult {
                        packages: cached.clone(),
                        depth: ResolutionDepth::Transitive,
                        direct_only_reason: None,
                        ..Default::default()
                    });
                }
                if go_package_manager_available() {
                    let work_dir = work_dir.clone();
                    let output = tokio::task::spawn_blocking(move || {
                        std::process::Command::new("go")
                            .args(["list", "-m", "all"])
                            .current_dir(&work_dir)
                            .output()
                    })
                    .await
                    .map_err(|e| {
                        ResolverError::Resolve(format!(
                            "go list task failed: {e}"
                        ))
                    })?
                    .map_err(ResolverError::Io)?;
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        match parse_go_list_m_all(&stdout) {
                            Ok(packages) => {
                                if let Ok(mut cache) = self.list_cache.lock() {
                                    cache.insert(cache_key, packages.clone());
                                }
                                return Ok(ResolveResult {
                                    packages,
                                    depth: ResolutionDepth::Transitive,
                                    direct_only_reason: None,
                                    ..Default::default()
                                });
                            }
                            Err(parse_err) => {
                                return require_transitive_or_fallback(
                                    graph,
                                    ctx,
                                    Some(parse_err),
                                );
                            }
                        }
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let snippet = stderr.trim();
                        let cause_msg = if snippet.is_empty() {
                            format!("go list exited with {}", output.status)
                        } else {
                            format!("go list failed: {snippet}")
                        };
                        return require_transitive_or_fallback(
                            graph,
                            ctx,
                            Some(ResolverError::Resolve(cause_msg)),
                        );
                    }
                }
                return require_transitive_or_fallback(graph, ctx, None);
            }
        }
        Err(fr022_transitive_error())
    }

    fn package_manager_available(&self) -> bool {
        go_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        go_package_manager_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_go_mod_dir_returns_parent() {
        let path = std::path::PathBuf::from("/foo/bar/go.mod");
        let dir = find_go_mod_dir(&path);
        assert_eq!(dir.as_deref(), Some(std::path::Path::new("/foo/bar")));
    }

    #[test]
    fn parse_go_list_m_all_output() {
        let content = r#"example.com/main
github.com/gin-gonic/gin v1.9.0
github.com/stretchr/testify v1.8.0
"#;
        let packages = parse_go_list_m_all(content).unwrap();
        assert!(packages.len() >= 2);
        assert!(
            packages.iter().any(|p| p.name == "github.com/gin-gonic/gin"
                && p.version == "v1.9.0")
        );
    }

    #[test]
    fn go_package_manager_hint_non_empty() {
        let hint = go_package_manager_hint();
        assert!(!hint.is_empty());
        assert!(
            hint.contains("go") || hint.contains("Go"),
            "hint should mention go"
        );
    }

    #[tokio::test]
    async fn go_resolver_returns_fr022_when_no_manifest_path() {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "github.com/foo/bar".to_string(),
                version: "v1.0.0".to_string(),
                ecosystem: Some(GO_ECOSYSTEM.to_string()),
            }],
            manifest_path: None,
        };
        let resolver = GoResolver::new();
        let err = resolver
            .resolve(&graph, &vlz_manifest_parser::ResolveContext::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            )
        );
    }

    #[tokio::test]
    async fn go_resolver_offline_skips_go_list() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("go.mod"),
            "module example.com/test\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
        )
        .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "github.com/gin-gonic/gin".to_string(),
                version: "v1.9.0".to_string(),
                ecosystem: Some(GO_ECOSYSTEM.to_string()),
            }],
            manifest_path: Some(tmp.join("go.mod")),
        };
        let resolver = GoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: false,
            ..Default::default()
        };
        let resolved = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(resolved.packages.len(), 1);
        assert_eq!(
            resolved.direct_only_reason,
            Some(vlz_manifest_parser::DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[tokio::test]
    async fn go_resolver_benchmark_skips_go_list() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(tmp.join("go.mod"), "module example.com/test\n")
            .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "github.com/gin-gonic/gin".to_string(),
                version: "v1.9.0".to_string(),
                ecosystem: Some(GO_ECOSYSTEM.to_string()),
            }],
            manifest_path: Some(tmp.join("go.mod")),
        };
        let resolver = GoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: true,
            ..Default::default()
        };
        let resolved = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(
            resolved.direct_only_reason,
            Some(vlz_manifest_parser::DIRECT_ONLY_REASON_BENCHMARK)
        );
    }

    #[tokio::test]
    async fn go_resolver_without_go_returns_fr022_or_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp).unwrap();
        std::fs::write(tmp.join("go.mod"), "module example.com/test\n")
            .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "github.com/gin-gonic/gin".to_string(),
                version: "v1.9.0".to_string(),
                ecosystem: Some(GO_ECOSYSTEM.to_string()),
            }],
            manifest_path: Some(tmp.join("go.mod")),
        };
        let resolver = GoResolver::new();
        match resolver
            .resolve(&graph, &vlz_manifest_parser::ResolveContext::default())
            .await
        {
            Ok(resolved) => {
                assert_eq!(
                    resolved.depth,
                    vlz_manifest_parser::ResolutionDepth::Transitive
                );
            }
            Err(err) => {
                assert!(err.to_string().contains(
                    vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
                ));
            }
        }
    }

    #[test]
    fn resolver_package_manager_available_and_hint() {
        let resolver = GoResolver::new();
        let _ = resolver.package_manager_available();
        let hint = resolver.package_manager_hint();
        assert!(!hint.is_empty());
    }
}
