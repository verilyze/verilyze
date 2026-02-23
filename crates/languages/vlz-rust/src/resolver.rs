// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use async_trait::async_trait;
use vlz_manifest_parser::{DependencyGraph, Resolver, ResolverError};

/// Find Cargo.lock next to the manifest or in parent dirs (workspace root).
pub fn find_lock_file(manifest_path: &Path) -> Option<std::path::PathBuf> {
    let dir = manifest_path.parent()?;
    let lock_path = dir.join("Cargo.lock");
    if lock_path.exists() && lock_path.is_file() {
        return Some(lock_path);
    }
    dir.parent()
        .and_then(|p| find_lock_file(&p.join("Cargo.toml")))
}

/// Parse Cargo.lock content into a list of packages. Public for fuzzing.
pub fn parse_cargo_lock(
    content: &str,
) -> Result<Vec<vlz_db::Package>, vlz_manifest_parser::ParserError> {
    let value: toml::Value = toml::from_str(content).map_err(|e| {
        vlz_manifest_parser::ParserError::Parse(format!(
            "Cargo.lock parse error: {}",
            e
        ))
    })?;

    let mut packages = Vec::new();
    if let Some(arr) = value.get("package").and_then(|p| p.as_array()) {
        for entry in arr {
            if let Some(tbl) = entry.as_table()
                && let Some(name) = tbl.get("name").and_then(|n| n.as_str())
            {
                let version = tbl
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("any")
                    .to_string();
                packages.push(vlz_db::Package {
                    name: name.to_string(),
                    version,
                    ecosystem: Some("crates.io".to_string()),
                });
            }
        }
    }
    Ok(packages)
}

/// Resolver that prefers Cargo.lock, falls back to graph packages.
#[derive(Debug, Default)]
pub struct CargoResolver;

impl CargoResolver {
    /// Create a new Cargo resolver.
    pub fn new() -> Self {
        Self
    }
}

/// Returns true if cargo appears to be on PATH (FR-024).
pub fn cargo_package_manager_available() -> bool {
    std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// OS-specific hint when cargo is missing (FR-024).
pub fn cargo_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: rustup (https://rustup.rs) or apt-get install cargo (Debian/Ubuntu).";
    #[cfg(target_os = "macos")]
    return "Install via: brew install rust or rustup (https://rustup.rs).";
    #[cfg(target_os = "windows")]
    return "Install Rust from https://rustup.rs/ and ensure cargo is on PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Rust and Cargo for your platform (https://rustup.rs).";
}

#[async_trait]
impl Resolver for CargoResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
    ) -> Result<Vec<vlz_db::Package>, ResolverError> {
        if let Some(ref manifest_path) = graph.manifest_path
            && let Some(lock_path) = find_lock_file(manifest_path)
            && let Ok(content) = std::fs::read_to_string(&lock_path)
            && let Ok(packages) = parse_cargo_lock(&content)
            && !packages.is_empty()
        {
            return Ok(packages);
        }
        Ok(graph.packages.clone())
    }

    fn package_manager_available(&self) -> bool {
        cargo_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        cargo_package_manager_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_lock_file_same_dir() {
        let tmp = std::env::temp_dir().join("vlz_rust_resolver_lock_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(tmp.join("Cargo.lock"), "version = 3\n").unwrap();

        let found = find_lock_file(tmp.join("Cargo.toml").as_path());
        assert_eq!(found.as_deref(), Some(tmp.join("Cargo.lock").as_path()));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_cargo_lock_packages() {
        let content = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tokio"
version = "1.0"
"#;
        let packages = parse_cargo_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "serde" && p.version == "1.0.0")
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "tokio" && p.version == "1.0")
        );
    }

    #[test]
    fn cargo_package_manager_hint_non_empty() {
        let hint = cargo_package_manager_hint();
        assert!(!hint.is_empty());
        assert!(
            hint.contains("cargo")
                || hint.contains("Rust")
                || hint.contains("rustup"),
            "hint should mention cargo or Rust"
        );
    }

    #[tokio::test]
    async fn cargo_resolver_returns_graph_when_no_lock() {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some("crates.io".to_string()),
            }],
            manifest_path: None,
        };
        let resolver = CargoResolver::new();
        let resolved = resolver.resolve(&graph).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "serde");
    }

    #[tokio::test]
    async fn cargo_resolver_uses_lock_when_present() {
        let tmp = std::env::temp_dir().join("vlz_rust_resolver_uses_lock");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("Cargo.toml"),
            r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "serde"
version = "1.0.2"

[[package]]
name = "serde_derive"
version = "1.0.2"
"#,
        )
        .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some("crates.io".to_string()),
            }],
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let resolved = resolver.resolve(&graph).await.unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(
            resolved
                .iter()
                .any(|p| p.name == "serde" && p.version == "1.0.2")
        );
        assert!(resolved.iter().any(|p| p.name == "serde_derive"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn cargo_resolver_fallback_when_lock_empty() {
        let tmp = std::env::temp_dir().join("vlz_rust_resolver_lock_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(tmp.join("Cargo.lock"), "version = 3\n").unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some("crates.io".to_string()),
            }],
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let resolved = resolver.resolve(&graph).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "serde");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn find_lock_file_parent_dir() {
        let tmp = std::env::temp_dir().join("vlz_rust_resolver_lock_parent");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("crates/foo")).unwrap();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(tmp.join("Cargo.lock"), "version = 3\n").unwrap();
        std::fs::write(tmp.join("crates/foo/Cargo.toml"), "[package]\n")
            .unwrap();

        let found =
            find_lock_file(tmp.join("crates/foo/Cargo.toml").as_path());
        assert_eq!(found.as_deref(), Some(tmp.join("Cargo.lock").as_path()));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_cargo_lock_package_without_version() {
        let content = r#"
version = 3

[[package]]
name = "noversion"
"#;
        let packages = parse_cargo_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "noversion");
        assert_eq!(packages[0].version, "any");
    }

    #[test]
    fn parse_cargo_lock_malformed_returns_error() {
        let content = "invalid {{{";
        let err = parse_cargo_lock(content).unwrap_err();
        assert!(format!("{:?}", err).contains("parse"));
    }

    #[test]
    fn resolver_package_manager_available_and_hint() {
        let resolver = CargoResolver::new();
        let _ = resolver.package_manager_available();
        let hint = resolver.package_manager_hint();
        assert!(!hint.is_empty());
    }
}
