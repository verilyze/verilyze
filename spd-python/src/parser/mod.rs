// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod pipfile;
mod pyproject;
mod requirements;
mod setup_cfg;

use async_trait::async_trait;
use std::path::PathBuf;

use spd_manifest_parser::{DependencyGraph, Parser, ParserError};

pub use pipfile::parse_pipfile;
pub use pyproject::parse_pyproject_toml;
pub use requirements::parse_requirements_txt;
pub use setup_cfg::parse_setup_cfg;

/// Parser for Python manifest files (requirements.txt, pyproject.toml, etc.).
/// Dispatches by manifest file name; returns empty graph for unsupported types.
#[derive(Debug, Default)]
pub struct RequirementsTxtParser;

impl RequirementsTxtParser {
    /// Create a new Python manifest parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for RequirementsTxtParser {
    async fn parse(&self, manifest: &PathBuf) -> Result<DependencyGraph, ParserError> {
        let name = manifest.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let manifest_path = Some(manifest.clone());

        if name == "requirements.txt" {
            let content = std::fs::read_to_string(manifest)?;
            let packages = parse_requirements_txt(&content)?;
            return Ok(DependencyGraph {
                packages,
                manifest_path,
            });
        }

        if name == "pyproject.toml" {
            let content = std::fs::read_to_string(manifest)?;
            let packages = parse_pyproject_toml(&content)?;
            return Ok(DependencyGraph {
                packages,
                manifest_path,
            });
        }

        if name == "Pipfile" {
            let content = std::fs::read_to_string(manifest)?;
            let packages = parse_pipfile(&content)?;
            return Ok(DependencyGraph {
                packages,
                manifest_path,
            });
        }

        if name == "setup.cfg" {
            let content = std::fs::read_to_string(manifest)?;
            let packages = parse_setup_cfg(&content)?;
            return Ok(DependencyGraph {
                packages,
                manifest_path,
            });
        }

        Ok(DependencyGraph {
            packages: Vec::new(),
            manifest_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_manifest_returns_empty_graph() {
        let parser = RequirementsTxtParser::new();
        let path = PathBuf::from("/some/path/setup.py");
        let graph = parser.parse(&path).await.unwrap();
        assert!(graph.packages.is_empty());
        assert_eq!(graph.manifest_path.as_deref(), Some(path.as_path()));
    }
}
