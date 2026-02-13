// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;

use spd_manifest_parser::{DependencyGraph, Resolver, ResolverError};

/// Resolver that returns direct dependencies only (no lock file / package manager).
#[derive(Debug, Default)]
pub struct DirectOnlyResolver;

impl DirectOnlyResolver {
    /// Create a new direct-only resolver.
    pub fn new() -> Self {
        Self
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
    ) -> Result<Vec<spd_db::Package>, ResolverError> {
        Ok(graph.packages.clone())
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

    #[test]
    fn package_manager_hint_returns_non_empty() {
        let hint = python_package_manager_hint();
        assert!(!hint.is_empty(), "hint must not be empty");
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
    fn python_package_manager_available_consistent() {
        let a = python_package_manager_available();
        let b = python_package_manager_available();
        assert_eq!(a, b, "result should be consistent (env-dependent)");
    }

    #[test]
    fn direct_only_resolver_implements_package_manager_methods() {
        let r = DirectOnlyResolver::new();
        let _ = r.package_manager_available();
        let hint = r.package_manager_hint();
        assert!(!hint.is_empty());
    }

    #[tokio::test]
    async fn direct_only_resolver_returns_graph_packages() {
        let graph = DependencyGraph {
            packages: vec![
                spd_db::Package {
                    name: "a".to_string(),
                    version: "1".to_string(),
                },
                spd_db::Package {
                    name: "b".to_string(),
                    version: "2".to_string(),
                },
            ],
        };
        let resolver = DirectOnlyResolver::new();
        let resolved = resolver.resolve(&graph).await.unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "a");
        assert_eq!(resolved[1].name, "b");
    }
}
