// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort parsers for local NuGet restore outputs (`project.assets.json`,
//! `*.deps.json`).

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;
use vlz_db::{DeclarationKind, NUGET_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::packages_lock::{is_nuget_package_name, normalize_nuget_version};

/// Parse `project.assets.json` library pins.
pub fn parse_project_assets_json(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_project_assets_json_with_declarations(
        content,
        Path::new("project.assets.json"),
    )?
    .0)
}

/// Parse `project.assets.json` with declaration metadata.
pub fn parse_project_assets_json_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    parse_libraries_section(content, path, "project.assets.json")
}

/// Parse `*.deps.json` library pins.
pub fn parse_deps_json(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(
        parse_deps_json_with_declarations(
            content,
            Path::new("App.deps.json"),
        )?
        .0,
    )
}

/// Parse `*.deps.json` with declaration metadata.
pub fn parse_deps_json_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let label = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("deps.json");
    parse_libraries_section(content, path, label)
}

fn parse_libraries_section(
    content: &str,
    path: &Path,
    label: &str,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let value: Value = serde_json::from_str(content).map_err(|e| {
        ParserError::Parse(format!("{label} parse error: {e}"))
    })?;
    let libraries = value
        .get("libraries")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            ParserError::Parse(format!("{label} missing libraries section"))
        })?;

    let mut packages = Vec::new();
    let mut parsed = Vec::new();
    let mut seen = HashSet::new();
    for (key, entry) in libraries {
        let entry_type = entry
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("package");
        if !entry_type.eq_ignore_ascii_case("package") {
            continue;
        }
        let Some((name, version)) = split_library_key(key) else {
            continue;
        };
        if !is_nuget_package_name(&name) {
            continue;
        }
        let version = normalize_nuget_version(&version);
        if version.is_empty() {
            continue;
        }
        let key = (name.clone(), version.clone());
        if !seen.insert(key) {
            continue;
        }
        let pkg = Package {
            name,
            version,
            ecosystem: Some(NUGET_ECOSYSTEM.to_string()),
        };
        packages.push(pkg.clone());
        parsed.push(ParsedDependency {
            package: pkg,
            path: path.to_path_buf(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        });
    }

    Ok((packages, parsed))
}

fn split_library_key(key: &str) -> Option<(String, String)> {
    let slash = key.rfind('/')?;
    let name = key[..slash].to_string();
    let version = key[slash + 1..].to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSETS: &str = r#"{
  "version": 3,
  "libraries": {
    "Newtonsoft.Json/13.0.3": {
      "type": "package",
      "serviceable": true,
      "sha512": "abc",
      "path": "newtonsoft.json/13.0.3"
    },
    "MyApp/1.0.0": {
      "type": "project",
      "serviceable": false
    }
  }
}"#;

    #[test]
    fn parse_project_assets_libraries() {
        let packages = parse_project_assets_json(ASSETS).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Newtonsoft.Json");
        assert_eq!(packages[0].version, "13.0.3");
    }

    #[test]
    fn parse_deps_json_libraries() {
        let packages = parse_deps_json(ASSETS).unwrap();
        assert_eq!(packages.len(), 1);
    }
}
