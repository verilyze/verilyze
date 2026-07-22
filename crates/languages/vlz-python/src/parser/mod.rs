// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod decl_spans;
mod lockfile;
mod pep508;
mod pipfile;
mod pyproject;
mod requirements;
mod setup_cfg;
mod setup_py;

use async_trait::async_trait;

use decl_spans::{
    graph_from_packages, graph_from_parsed, parsed_from_packages,
    scan_toml_dep_keys,
};
use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

use crate::lock_names::is_python_lock_file;

pub use lockfile::{
    parse_lock_file, parse_lock_file_with_declarations, parse_pylock_toml,
};
pub use pipfile::parse_pipfile;
pub use pyproject::parse_pyproject_toml;
pub use requirements::{
    parse_requirements_txt, parse_requirements_txt_with_declarations,
};
pub use setup_cfg::{parse_setup_cfg, parse_setup_cfg_with_declarations};
pub use setup_py::{parse_setup_py, parse_setup_py_with_declarations};

/// Parser for Python manifest files (requirements.txt, pyproject.toml, etc.).
/// Dispatches by manifest file name; returns empty graph for unknown types
/// (callers should only pass files found by the PythonManifestFinder).
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
    async fn parse(
        &self,
        manifest: &std::path::Path,
    ) -> Result<DependencyGraph, ParserError> {
        let name = manifest.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let manifest_path = Some(manifest.to_path_buf());

        if name == "requirements.txt" {
            let content = tokio::fs::read_to_string(manifest).await?;
            let parsed =
                parse_requirements_txt_with_declarations(&content, manifest)?;
            return Ok(graph_from_parsed(parsed, manifest_path));
        }

        if name == "pyproject.toml" {
            let content = tokio::fs::read_to_string(manifest).await?;
            let packages = parse_pyproject_toml(&content)?;
            let lines = scan_toml_dep_keys(&content);
            let parsed =
                parsed_from_packages(packages.clone(), manifest, &lines);
            return Ok(graph_from_packages(packages, parsed, manifest_path));
        }

        if name == "Pipfile" {
            let content = tokio::fs::read_to_string(manifest).await?;
            let packages = parse_pipfile(&content)?;
            let lines = scan_toml_dep_keys(&content);
            let parsed =
                parsed_from_packages(packages.clone(), manifest, &lines);
            return Ok(graph_from_packages(packages, parsed, manifest_path));
        }

        if name == "setup.cfg" {
            let content = tokio::fs::read_to_string(manifest).await?;
            let parsed =
                parse_setup_cfg_with_declarations(&content, manifest)?;
            return Ok(graph_from_parsed(parsed, manifest_path));
        }

        if name == "setup.py" {
            let content = tokio::fs::read_to_string(manifest).await?;
            let parsed = parse_setup_py_with_declarations(&content, manifest)?;
            return Ok(graph_from_parsed(parsed, manifest_path));
        }

        if is_python_lock_file(name) {
            let content = tokio::fs::read_to_string(manifest).await?;
            let (packages, parsed) =
                parse_lock_file_with_declarations(manifest, &content)?;
            if parsed.is_empty() {
                return Ok(DependencyGraph {
                    packages,
                    parsed_dependencies: Vec::new(),
                    manifest_path,
                });
            }
            return Ok(graph_from_parsed(parsed, manifest_path));
        }

        Ok(DependencyGraph {
            packages: Vec::new(),
            parsed_dependencies: Vec::new(),
            manifest_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn parse_orphan_pylock_entry_point() {
        let dir = tempfile::tempdir().unwrap();
        let pylock = dir.path().join("pylock.toml");
        std::fs::write(
            &pylock,
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let parser = RequirementsTxtParser::new();
        let graph = parser.parse(&pylock).await.unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "pkg");
    }

    #[tokio::test]
    async fn parse_valid_empty_pylock_returns_empty_packages() {
        let dir = tempfile::tempdir().unwrap();
        let pylock = dir.path().join("pylock.toml");
        std::fs::write(
            &pylock,
            "lock-version = \"1.0\"\ncreated-by = \"test\"\npackages = []\n",
        )
        .unwrap();
        let parser = RequirementsTxtParser::new();
        let graph = parser.parse(&pylock).await.unwrap();
        assert!(graph.packages.is_empty());
    }

    #[tokio::test]
    async fn unknown_manifest_fallthrough_returns_empty_graph() {
        // An unrecognised file name that somehow reaches the parser returns
        // an empty graph (defensive fallthrough). The finder is responsible
        // for only passing known manifest files; this covers the fallthrough.
        let parser = RequirementsTxtParser::new();
        let path = PathBuf::from("/some/path/requirements.pip");
        let graph = parser.parse(&path).await.unwrap();
        assert!(graph.packages.is_empty());
        assert_eq!(graph.manifest_path.as_deref(), Some(path.as_path()));
    }
}
