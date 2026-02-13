// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::PathBuf;

use spd_manifest_parser::{DependencyGraph, Parser, ParserError};

/// Parser for `requirements.txt` files.
/// For other manifest paths (e.g. `pyproject.toml`) returns an empty graph so the scan can continue.
#[derive(Debug, Default)]
pub struct RequirementsTxtParser;

impl RequirementsTxtParser {
    /// Create a new requirements.txt parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for RequirementsTxtParser {
    async fn parse(&self, manifest: &PathBuf) -> Result<DependencyGraph, ParserError> {
        let name = manifest.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name != "requirements.txt" {
            return Ok(DependencyGraph::default());
        }
        let content = std::fs::read_to_string(manifest)?;
        let packages = parse_requirements_txt(&content)?;
        Ok(DependencyGraph { packages })
    }
}

/// Parse requirements.txt content into a list of packages (name, version).
/// Skips comments, empty lines, and directive lines (-r, -e, etc.).
/// Version: exact from `==`, first version from `>=`/`<=`/`~=`, else `"any"`.
/// Public for fuzzing (NFR-020).
pub fn parse_requirements_txt(content: &str) -> Result<Vec<spd_db::Package>, ParserError> {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-r ")
            || line.starts_with("-e ")
            || line.starts_with("--")
            || line.starts_with("-f ")
            || line.starts_with("-i ")
        {
            continue;
        }
        if let Some(pkg) = parse_requirement_line(line) {
            packages.push(pkg);
        }
    }
    Ok(packages)
}

/// Parse a single requirement line into Package (name, version), or None if unparseable.
fn parse_requirement_line(line: &str) -> Option<spd_db::Package> {
    // Strip inline comment
    let line = line
        .find('#')
        .map(|i| line[..i].trim())
        .unwrap_or(line)
        .trim();
    if line.is_empty() {
        return None;
    }
    // PEP 508: name may have [extras]; strip extras so we get "name" and version spec
    let spec = if let Some(open) = line.find('[') {
        let after_close = line[open..]
            .find(']')
            .map(|c| open + c + 1)
            .unwrap_or(line.len());
        format!("{}{}", line[..open].trim(), line[after_close..].trim())
    } else {
        line.to_string()
    };
    let (name, version) = parse_name_version(&spec)?;
    if name.is_empty() {
        return None;
    }
    Some(spd_db::Package { name, version })
}

/// Split a requirement spec (no [extras]) into (name, version).
fn parse_name_version(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    // Exact version: name==1.0.0
    if let Some((n, v)) = spec.split_once("==") {
        return Some((n.trim().to_string(), v.trim().to_string()));
    }
    // Version specifiers: take first version-like part
    for sep in ["~=", ">=", "<=", "!=", ">", "<"] {
        if let Some((n, v)) = spec.split_once(sep) {
            let version = v.trim().split(',').next().unwrap_or("").trim().to_string();
            let version = if version.is_empty() {
                "any".to_string()
            } else {
                version
            };
            return Some((n.trim().to_string(), version));
        }
    }
    // No version: name only
    Some((spec.to_string(), "any".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[tokio::test]
    async fn parse_requirements_txt_file() {
        let tmp = std::env::temp_dir().join("spd_python_parser_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("requirements.txt");
        std::fs::write(
            &path,
            b"# comment\n\
              foo==1.0.0\n\
              bar>=2.0\n\
              baz\n\
              \n\
              qux~=3.1\n\
              --extra-index-url https://example.com\n\
              pkg[dev]==1.0\n\
              \t # inline with nothing before\n\
              ==1.0\n\
              []\n",
        )
        .unwrap();
        let parser = RequirementsTxtParser::new();
        let graph = parser.parse(&path).await.unwrap();
        assert_eq!(graph.packages.len(), 5);
        let names: Vec<_> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["foo", "bar", "baz", "qux", "pkg"]);
        assert_eq!(graph.packages[0].version, "1.0.0");
        assert_eq!(graph.packages[1].version, "2.0");
        assert_eq!(graph.packages[2].version, "any");
        assert_eq!(graph.packages[3].version, "3.1");
        assert_eq!(graph.packages[4].version, "1.0");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn non_requirements_path_returns_empty_graph() {
        let parser = RequirementsTxtParser::new();
        let path = PathBuf::from("/some/path/pyproject.toml");
        let graph = parser.parse(&path).await.unwrap();
        assert!(graph.packages.is_empty());
    }

    #[tokio::test]
    async fn parse_nonexistent_requirements_txt_returns_error() {
        let parser = RequirementsTxtParser::new();
        let path = PathBuf::from("/nonexistent/path/requirements.txt");
        let err = parser.parse(&path).await.unwrap_err();
        let msg = err.to_string();
        let source_msg = err
            .source()
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(
            msg.contains("IO") || msg.contains("manifest")
                || source_msg.contains("No such file")
                || source_msg.contains("not found"),
            "expected file-not-found error, got: {} (source: {})",
            msg,
            source_msg
        );
    }

    #[test]
    fn parse_requirement_line_strips_extras() {
        let pkg = parse_requirement_line("foo[dev]==1.0").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_requirement_line_skips_empty_after_comment() {
        assert!(parse_requirement_line("  # x").is_none());
    }

    #[test]
    fn parse_requirement_line_skips_empty_name() {
        assert!(parse_requirement_line("==1.0").is_none());
    }

    #[test]
    fn parse_requirement_line_skips_brackets_only() {
        assert!(parse_requirement_line("[]").is_none());
    }

    #[test]
    fn parse_requirements_txt_skips_double_dash_directive() {
        let content = "foo==1.0\n--extra-index-url https://pypi.org\nbar>=2.0\n";
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[1].name, "bar");
    }
}
