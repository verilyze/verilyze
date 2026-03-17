// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use vlz_manifest_parser::{DependencyGraph, Resolver, ResolverError};

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
    ) -> Result<Vec<vlz_db::Package>, ResolverError> {
        if let Some(ref manifest_path) = graph.manifest_path {
            let dir = find_go_mod_dir(manifest_path);
            if let Some(ref work_dir) = dir {
                let cache_key = work_dir.to_string_lossy().to_string();
                if let Ok(cache) = self.list_cache.lock()
                    && let Some(cached) = cache.get(&cache_key)
                    && !cached.is_empty()
                {
                    return Ok(cached.clone());
                }
                if go_package_manager_available() {
                    let output = std::process::Command::new("go")
                        .args(["list", "-m", "all"])
                        .current_dir(work_dir)
                        .output()
                        .map_err(ResolverError::Io)?;
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if let Ok(packages) = parse_go_list_m_all(&stdout)
                            && !packages.is_empty()
                        {
                            if let Ok(mut cache) = self.list_cache.lock() {
                                cache.insert(cache_key, packages.clone());
                            }
                            return Ok(packages);
                        }
                    }
                }
            }
        }
        Ok(graph.packages.clone())
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
    async fn go_resolver_returns_graph_when_no_manifest_path() {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "github.com/foo/bar".to_string(),
                version: "v1.0.0".to_string(),
                ecosystem: Some(GO_ECOSYSTEM.to_string()),
            }],
            manifest_path: None,
        };
        let resolver = GoResolver::new();
        let resolved = resolver.resolve(&graph).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "github.com/foo/bar");
    }

    #[tokio::test]
    async fn go_resolver_fallback_to_graph() {
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
        let resolved = resolver.resolve(&graph).await.unwrap();
        assert!(!resolved.is_empty());
        assert!(
            resolved
                .iter()
                .any(|p| p.name == "github.com/gin-gonic/gin")
        );
    }

    #[test]
    fn resolver_package_manager_available_and_hint() {
        let resolver = GoResolver::new();
        let _ = resolver.package_manager_available();
        let hint = resolver.package_manager_hint();
        assert!(!hint.is_empty());
    }
}
