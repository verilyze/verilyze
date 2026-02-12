// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

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
        let content =
            std::fs::read_to_string(manifest).map_err(|e| ParserError::Other(e.to_string()))?;
        let packages = parse_requirements_txt(&content)?;
        Ok(DependencyGraph { packages })
    }
}

/// Parse requirements.txt content into a list of packages (name, version).
/// Skips comments, empty lines, and directive lines (-r, -e, etc.).
/// Version: exact from `==`, first version from `>=`/`<=`/`~=`, else `"any"`.
fn parse_requirements_txt(content: &str) -> Result<Vec<spd_db::Package>, ParserError> {
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
              qux~=3.1\n",
        )
        .unwrap();
        let parser = RequirementsTxtParser::new();
        let graph = parser.parse(&path).await.unwrap();
        assert_eq!(graph.packages.len(), 4);
        let names: Vec<_> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["foo", "bar", "baz", "qux"]);
        assert_eq!(graph.packages[0].version, "1.0.0");
        assert_eq!(graph.packages[1].version, "2.0");
        assert_eq!(graph.packages[2].version, "any");
        assert_eq!(graph.packages[3].version, "3.1");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn non_requirements_path_returns_empty_graph() {
        let parser = RequirementsTxtParser::new();
        let path = PathBuf::from("/some/path/pyproject.toml");
        let graph = parser.parse(&path).await.unwrap();
        assert!(graph.packages.is_empty());
    }
}
