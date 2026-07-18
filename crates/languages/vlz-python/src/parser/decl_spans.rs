// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use vlz_db::DeclarationKind;
use vlz_db::Package;
use vlz_manifest_parser::{DependencyGraph, ParsedDependency};

/// Build a dependency graph from parsed manifest dependencies.
pub fn graph_from_parsed(
    parsed_dependencies: Vec<ParsedDependency>,
    manifest_path: Option<PathBuf>,
) -> DependencyGraph {
    let packages = parsed_dependencies
        .iter()
        .map(|dep| dep.package.clone())
        .collect();
    graph_from_packages(packages, parsed_dependencies, manifest_path)
}

/// Build a dependency graph from semantic packages plus optional declaration metadata.
pub fn graph_from_packages(
    packages: Vec<Package>,
    parsed_dependencies: Vec<ParsedDependency>,
    manifest_path: Option<PathBuf>,
) -> DependencyGraph {
    DependencyGraph {
        packages,
        parsed_dependencies,
        manifest_path,
    }
}

/// Attach line numbers to semantically parsed packages using a name-to-line map.
pub fn parsed_from_packages(
    packages: Vec<Package>,
    path: &Path,
    name_to_line: &HashMap<String, u32>,
) -> Vec<ParsedDependency> {
    packages
        .into_iter()
        .filter_map(|package| {
            name_to_line.get(&package.name).map(|start_line| {
                ParsedDependency {
                    package,
                    path: path.to_path_buf(),
                    start_line: *start_line,
                    end_line: None,
                    kind: DeclarationKind::Manifest,
                }
            })
        })
        .collect()
}

/// Scan TOML-ish manifest lines for `name =` dependency keys.
pub fn scan_toml_dep_keys(content: &str) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    for (i, line) in content.lines().enumerate() {
        let line_no = (i + 1) as u32;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            let name = name.trim().trim_matches('"').to_string();
            if !name.is_empty() {
                out.entry(name).or_insert(line_no);
            }
        }
    }
    out
}
