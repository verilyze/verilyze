// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::PathBuf;

use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

/// Parse Cargo.toml content into a list of packages from [dependencies],
/// [dev-dependencies], and [build-dependencies]. Public for fuzzing (NFR-020).
pub fn parse_cargo_toml(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let value: toml::Value = toml::from_str(content)
        .map_err(|e| ParserError::Parse(format!("Cargo.toml parse error: {}", e)))?;

    let mut packages = Vec::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = value.get(section).and_then(|d| d.as_table()) {
            for (name, val) in deps {
                if let Some(pkg) = parse_dependency_entry(name, val) {
                    packages.push(pkg);
                }
            }
        }
    }

    Ok(packages)
}

/// Parse a single dependency entry (string or table format).
fn parse_dependency_entry(name: &str, val: &toml::Value) -> Option<vlz_db::Package> {
    if let Some(s) = val.as_str() {
        let version = extract_version_from_req(s);
        return Some(vlz_db::Package {
            name: name.to_string(),
            version,
            ecosystem: Some("crates.io".to_string()),
        });
    }
    if let Some(tbl) = val.as_table() {
        if tbl.get("path").is_some() || tbl.get("git").is_some() {
            return Some(vlz_db::Package {
                name: name.to_string(),
                version: "any".to_string(),
                ecosystem: Some("crates.io".to_string()),
            });
        }
        let version = tbl
            .get("version")
            .and_then(|v| v.as_str())
            .map(extract_version_from_req)
            .unwrap_or_else(|| "any".to_string());
        return Some(vlz_db::Package {
            name: name.to_string(),
            version,
            ecosystem: Some("crates.io".to_string()),
        });
    }
    None
}

/// Extract a version-like string from a SemVer requirement (e.g. "1.0.0", ">=1.0", "any").
fn extract_version_from_req(req: &str) -> String {
    let req = req.trim();
    if req.is_empty() {
        return "any".to_string();
    }
    if let Some((_, v)) = req.split_once('=') {
        return v.trim().trim_matches('"').to_string();
    }
    for prefix in [">=", "<=", ">", "<", "~", "^"] {
        if let Some((_, v)) = req.split_once(prefix) {
            let v = v.trim().trim_matches('"').split(',').next().unwrap_or("").trim();
            return if v.is_empty() {
                "any".to_string()
            } else {
                v.to_string()
            };
        }
    }
    if req.starts_with('"') && req.ends_with('"') {
        return req[1..req.len() - 1].to_string();
    }
    req.to_string()
}

/// Parser for Rust Cargo.toml manifest files.
#[derive(Debug, Default)]
pub struct CargoTomlParser;

impl CargoTomlParser {
    /// Create a new Cargo.toml parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for CargoTomlParser {
    async fn parse(&self, manifest: &PathBuf) -> Result<DependencyGraph, ParserError> {
        let content = std::fs::read_to_string(manifest)?;
        let value: toml::Value = toml::from_str(&content)
            .map_err(|e| ParserError::Parse(format!("Cargo.toml parse error: {}", e)))?;

        let mut packages = parse_cargo_toml(&content)?;

        if let Some(workspace) = value.get("workspace") {
            if let Some(members) = workspace.get("members").and_then(|m| m.as_array()) {
                let manifest_dir = manifest
                    .parent()
                    .ok_or_else(|| ParserError::Other("manifest has no parent".to_string()))?;
                let member_paths = expand_workspace_members(manifest_dir, members);
                for member_manifest in member_paths {
                    if let Ok(c) = std::fs::read_to_string(&member_manifest) {
                        if let Ok(member_packages) = parse_cargo_toml(&c) {
                            for p in member_packages {
                                if !packages.iter().any(|x| x.name == p.name && x.version == p.version)
                                {
                                    packages.push(p);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(DependencyGraph {
            packages,
            manifest_path: Some(manifest.clone()),
        })
    }
}

/// Expand workspace member patterns relative to manifest dir (e.g. "crates/*", "packages/foo").
/// Returns paths to Cargo.toml files for each member. Simple glob: "crates/*" = all subdirs.
fn expand_workspace_members(
    manifest_dir: &std::path::Path,
    members: &[toml::Value],
) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    for m in members {
        let s = match m.as_str() {
            Some(s) => s,
            None => continue,
        };
        let pattern = manifest_dir.join(s);
        if pattern.exists() && pattern.is_dir() && pattern.join("Cargo.toml").exists() {
            result.push(pattern.join("Cargo.toml"));
        } else if s.contains('*') {
            let (prefix, _suffix) = s.split_once('*').unwrap_or((s, ""));
            let prefix_path = manifest_dir.join(prefix.trim_end_matches('/'));
            if let Ok(entries) = std::fs::read_dir(&prefix_path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() && p.join("Cargo.toml").exists() {
                        result.push(p.join("Cargo.toml"));
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_toml_dependencies() {
        let content = r#"
[package]
name = "foo"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
clap = ">= 4.0"
"#;
        let packages = parse_cargo_toml(content).unwrap();
        assert_eq!(packages.len(), 3);
        assert!(packages.iter().any(|p| p.name == "serde" && p.version == "1.0"));
        assert!(packages.iter().any(|p| p.name == "tokio" && p.version == "1.0"));
        assert!(packages.iter().any(|p| p.name == "clap"));
    }

    #[test]
    fn parse_cargo_toml_workspace_root_empty_deps() {
        let content = r#"
[workspace]
members = ["crates/*"]
"#;
        let packages = parse_cargo_toml(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn test_extract_version_from_req() {
        assert_eq!(super::extract_version_from_req("1.0.0"), "1.0.0");
        assert_eq!(super::extract_version_from_req("= 1.0.0"), "1.0.0");
        assert_eq!(super::extract_version_from_req(r#""1.0.0""#), "1.0.0");
        assert_eq!(super::extract_version_from_req(">= 1.0"), "1.0");
        assert_eq!(super::extract_version_from_req("^1.2"), "1.2");
        assert_eq!(super::extract_version_from_req("<= 2.0"), "2.0");
        assert_eq!(super::extract_version_from_req("> 0.5"), "0.5");
        assert_eq!(super::extract_version_from_req("< 3.0"), "3.0");
        assert_eq!(super::extract_version_from_req("~1.2"), "1.2");
        assert_eq!(super::extract_version_from_req(""), "any");
        assert_eq!(super::extract_version_from_req("   "), "any");
        assert_eq!(super::extract_version_from_req("^ "), "any");
    }

    #[test]
    fn parse_cargo_toml_path_and_git_deps() {
        let content = r#"
[package]
name = "foo"
version = "0.1.0"

[dependencies]
local = { path = "../local" }
gitdep = { git = "https://example.com/repo" }
tabled = { version = "1.0" }
"#;
        let packages = parse_cargo_toml(content).unwrap();
        assert_eq!(packages.len(), 3);
        assert!(packages.iter().any(|p| p.name == "local" && p.version == "any"));
        assert!(packages.iter().any(|p| p.name == "gitdep" && p.version == "any"));
        assert!(packages.iter().any(|p| p.name == "tabled" && p.version == "1.0"));
    }

    #[test]
    fn parse_cargo_toml_dev_and_build_deps() {
        let content = r#"
[package]
name = "foo"
version = "0.1.0"

[dev-dependencies]
devdep = "1.0"

[build-dependencies]
builddep = "2.0"
"#;
        let packages = parse_cargo_toml(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "devdep"));
        assert!(packages.iter().any(|p| p.name == "builddep"));
    }

    #[test]
    fn parse_cargo_toml_malformed_returns_error() {
        let content = "invalid toml {{{";
        let err = parse_cargo_toml(content).unwrap_err();
        assert!(format!("{:?}", err).contains("parse"));
    }

    #[test]
    fn parse_cargo_toml_table_without_version_uses_any() {
        let content = r#"
[dependencies]
no_version = {}
"#;
        let packages = parse_cargo_toml(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "no_version");
        assert_eq!(packages[0].version, "any");
    }

    #[tokio::test]
    async fn cargo_toml_parser_nonexistent_manifest_returns_error() {
        let parser = CargoTomlParser::new();
        let result = parser.parse(&std::path::PathBuf::from("/nonexistent/path/Cargo.toml")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn expand_workspace_members_explicit_path() {
        let tmp = std::env::temp_dir().join("vlz_rust_expand_explicit");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("packages/foo")).unwrap();
        std::fs::write(
            tmp.join("Cargo.toml"),
            r#"[workspace]
members = ["packages/foo"]
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("packages/foo/Cargo.toml"),
            r#"[package]
name = "foo"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();

        let parser = CargoTomlParser::new();
        let graph = parser.parse(&tmp.join("Cargo.toml")).await.unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "serde");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn cargo_toml_parser_returns_graph() {
        let tmp = std::env::temp_dir().join("vlz_rust_parser_test");
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

        let parser = CargoTomlParser::new();
        let graph = parser.parse(&tmp.join("Cargo.toml")).await.unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "serde");
        assert_eq!(graph.packages[0].version, "1.0");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn cargo_toml_parser_workspace_members() {
        let tmp = std::env::temp_dir().join("vlz_rust_parser_workspace_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("crates/foo")).unwrap();
        std::fs::create_dir_all(tmp.join("crates/bar")).unwrap();

        std::fs::write(
            tmp.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/*"]
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("crates/foo").join("Cargo.toml"),
            r#"[package]
name = "foo"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("crates/bar").join("Cargo.toml"),
            r#"[package]
name = "bar"
version = "0.1.0"

[dependencies]
tokio = "1.0"
"#,
        )
        .unwrap();

        let parser = CargoTomlParser::new();
        let graph = parser.parse(&tmp.join("Cargo.toml")).await.unwrap();
        assert_eq!(graph.packages.len(), 2);
        assert!(graph.packages.iter().any(|p| p.name == "serde"));
        assert!(graph.packages.iter().any(|p| p.name == "tokio"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
