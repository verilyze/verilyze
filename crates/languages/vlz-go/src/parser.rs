// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::Path;

use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

/// Go ecosystem for OSV.dev (PRD MOD-002, OSV schema).
pub const GO_ECOSYSTEM: &str = "Go";

/// Parse go.mod content into a list of packages from require blocks.
/// Excludes modules listed in replace and exclude directives.
/// Public for fuzzing (NFR-020).
pub fn parse_go_mod(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ParserError> {
    let (replaced, excluded) = parse_replace_and_exclude(content);
    let mut packages = Vec::new();

    let mut in_require = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require {
            if line == ")" {
                in_require = false;
                continue;
            }
            if let Some(pkg) = parse_require_line(line, &replaced, &excluded) {
                packages.push(pkg);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ").map(str::trim)
            && let Some(pkg) = parse_require_line(rest, &replaced, &excluded)
        {
            packages.push(pkg);
        }
    }

    Ok(packages)
}

/// Parse a single require line: "module/path v1.2.3" or "module/path v1.2.3 // indirect"
fn parse_require_line(
    line: &str,
    replaced: &std::collections::HashSet<String>,
    excluded: &std::collections::HashSet<(String, String)>,
) -> Option<vlz_db::Package> {
    let line = line.split("//").next().unwrap_or(line).trim();
    if line.is_empty() {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let module_path = parts[0];
    let version = parts[1];
    if replaced.contains(module_path) {
        return None;
    }
    if excluded.contains(&(module_path.to_string(), version.to_string())) {
        return None;
    }
    Some(vlz_db::Package {
        name: module_path.to_string(),
        version: version.to_string(),
        ecosystem: Some(GO_ECOSYSTEM.to_string()),
    })
}

/// Parse replace and exclude directives; return sets of module paths/versions
/// to skip. Replaced modules are skipped entirely; excluded are (path, version).
fn parse_replace_and_exclude(
    content: &str,
) -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<(String, String)>,
) {
    let mut replaced = std::collections::HashSet::new();
    let mut excluded = std::collections::HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("replace ") {
            if let Some(path) = extract_replace_module(line) {
                replaced.insert(path);
            }
        } else if line.starts_with("exclude ")
            && let Some((path, ver)) = extract_exclude_module_version(line)
        {
            excluded.insert((path, ver));
        }
    }

    (replaced, excluded)
}

/// Extract module path from "replace module => ..." or "replace module v1 => ..."
fn extract_replace_module(line: &str) -> Option<String> {
    let rest = line["replace ".len()..].trim();
    let before_arrow = rest.split("=>").next()?.trim();
    let parts: Vec<&str> = before_arrow.split_whitespace().collect();
    parts.first().map(|s| (*s).to_string())
}

/// Extract (module path, version) from "exclude module v1.2.3"
fn extract_exclude_module_version(line: &str) -> Option<(String, String)> {
    let rest = line["exclude ".len()..].trim();
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() >= 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Parser for Go go.mod manifest files.
#[derive(Debug, Default)]
pub struct GoModParser;

impl GoModParser {
    /// Create a new go.mod parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for GoModParser {
    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let content = tokio::fs::read_to_string(manifest).await?;
        let packages = parse_go_mod(&content)?;
        Ok(DependencyGraph {
            packages,
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_mod_require_block() {
        let content = r#"
module example.com/app
go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.0
)
"#;
        let packages = parse_go_mod(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(
            packages.iter().any(|p| p.name == "github.com/gin-gonic/gin"
                && p.version == "v1.9.0")
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "github.com/stretchr/testify"
                    && p.version == "v1.8.0")
        );
        assert!(
            packages
                .iter()
                .all(|p| p.ecosystem.as_deref() == Some(GO_ECOSYSTEM))
        );
    }

    #[test]
    fn parse_go_mod_indirect() {
        let content = r#"
module example.com/app
require (
    github.com/direct v1.0.0
    github.com/indirect v2.0.0 // indirect
)
"#;
        let packages = parse_go_mod(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "github.com/indirect"));
    }

    #[test]
    fn parse_go_mod_replace_excluded() {
        let content = r#"
module example.com/app
require (
    github.com/kept v1.0.0
    github.com/replaced v1.0.0
    github.com/excluded v1.0.0
)
replace github.com/replaced => ./local/replaced
exclude github.com/excluded v1.0.0
"#;
        let packages = parse_go_mod(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "github.com/kept");
    }

    #[test]
    fn parse_go_mod_single_line_require() {
        let content = r#"
module example.com/app
require github.com/foo v1.2.3
"#;
        let packages = parse_go_mod(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "github.com/foo");
        assert_eq!(packages[0].version, "v1.2.3");
    }

    #[test]
    fn parse_go_mod_pseudo_version() {
        let content = r#"
require (
    github.com/untagged v0.0.0-20210101000000-abcdef123456
)
"#;
        let packages = parse_go_mod(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].version, "v0.0.0-20210101000000-abcdef123456");
    }

    #[test]
    fn parse_go_mod_empty_returns_empty() {
        let content = "module example.com/app\n";
        let packages = parse_go_mod(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn go_ecosystem_constant() {
        assert_eq!(GO_ECOSYSTEM, "Go");
    }

    #[tokio::test]
    async fn go_mod_parser_returns_graph() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp).unwrap();
        std::fs::write(
            tmp.join("go.mod"),
            r#"module example.com/test
require github.com/gin-gonic/gin v1.9.0
"#,
        )
        .unwrap();

        let parser = GoModParser::new();
        let graph = parser.parse(&tmp.join("go.mod")).await.unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "github.com/gin-gonic/gin");
        assert_eq!(graph.packages[0].version, "v1.9.0");
    }
}
