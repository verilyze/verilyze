// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use vlz_db::{DeclarationKind, NPM_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

/// Metadata extracted from package.json for resolution.
#[derive(Debug, Clone, Default)]
pub struct PackageJsonMeta {
    pub package_manager: Option<String>,
    /// Package name from package.json when present (may be unused by resolver).
    #[allow(dead_code)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PackageJsonFile {
    name: Option<String>,
    #[serde(rename = "packageManager")]
    package_manager: Option<String>,
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: Option<BTreeMap<String, String>>,
}

/// True when the version/spec is a registry-style npm dependency (not
/// workspace/file/git/URL protocols).
pub fn is_registry_dependency_spec(spec: &str) -> bool {
    let s = spec.trim();
    if s.is_empty() {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    for prefix in [
        "workspace:",
        "file:",
        "link:",
        "portal:",
        "patch:",
        "git:",
        "git+",
        "github:",
        "gitlab:",
        "bitbucket:",
        "http://",
        "https://",
        "ssh://",
    ] {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// Parse package.json content into direct dependency packages.
/// Peers are excluded (prefer lockfile). Non-registry specs are skipped.
pub fn parse_package_json(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_package_json_with_declarations(
        content,
        Path::new("package.json"),
    )?
    .0)
}

/// Parse package.json and return packages plus Corepack metadata.
pub fn parse_package_json_with_meta(
    content: &str,
) -> Result<(Vec<Package>, PackageJsonMeta), ParserError> {
    let (packages, meta) = parse_inner(content, Path::new("package.json"))?;
    Ok((packages.into_iter().map(|p| p.package).collect(), meta))
}

/// Parse with declaration line metadata (FR-036a).
pub fn parse_package_json_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let (parsed, _meta) = parse_inner(content, path)?;
    let packages = parsed.iter().map(|p| p.package.clone()).collect();
    Ok((packages, parsed))
}

fn parse_inner(
    content: &str,
    path: &Path,
) -> Result<(Vec<ParsedDependency>, PackageJsonMeta), ParserError> {
    let file: PackageJsonFile =
        serde_json::from_str(content).map_err(|e| {
            ParserError::Parse(format!("package.json parse error: {e}"))
        })?;
    let meta = PackageJsonMeta {
        package_manager: file.package_manager.clone(),
        name: file.name.clone(),
    };

    let mut parsed = Vec::new();
    let line_map = dependency_name_lines(content);
    for (section, map) in [
        ("dependencies", file.dependencies.as_ref()),
        ("devDependencies", file.dev_dependencies.as_ref()),
        ("optionalDependencies", file.optional_dependencies.as_ref()),
    ] {
        let Some(deps) = map else {
            continue;
        };
        let _ = section;
        for (name, spec) in deps {
            if !is_registry_dependency_spec(spec) {
                continue;
            }
            let start_line = line_map.get(name.as_str()).copied().unwrap_or(1);
            parsed.push(ParsedDependency {
                package: Package {
                    name: name.clone(),
                    // Ranges are not OSV-ready; resolver prefers lock pins.
                    version: spec.clone(),
                    ecosystem: Some(NPM_ECOSYSTEM.to_string()),
                },
                path: path.to_path_buf(),
                start_line,
                end_line: None,
                kind: DeclarationKind::Manifest,
            });
        }
    }
    Ok((parsed, meta))
}

/// Best-effort map of dependency name -> line number in package.json text.
fn dependency_name_lines(content: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Match "name": "spec" or "name":"spec"
        if let Some(rest) = trimmed.strip_prefix('"')
            && let Some(end) = rest.find('"')
        {
            let name = &rest[..end];
            let after = &rest[end + 1..];
            if after.trim_start().starts_with(':') {
                out.insert(name.to_string(), (i + 1) as u32);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_json_deps_and_dev() {
        let content = r#"{
  "name": "app",
  "dependencies": { "lodash": "^4.17.21" },
  "devDependencies": { "typescript": "~5.0.0" },
  "optionalDependencies": { "fsevents": "2.3.0" },
  "peerDependencies": { "react": "^18.0.0" }
}"#;
        let packages = parse_package_json(content).unwrap();
        assert_eq!(packages.len(), 3);
        assert!(packages.iter().any(|p| p.name == "lodash"));
        assert!(packages.iter().any(|p| p.name == "typescript"));
        assert!(packages.iter().any(|p| p.name == "fsevents"));
        assert!(!packages.iter().any(|p| p.name == "react"));
        assert!(
            packages
                .iter()
                .all(|p| p.ecosystem.as_deref() == Some(NPM_ECOSYSTEM))
        );
    }

    #[test]
    fn skips_workspace_and_file_specs() {
        let content = r#"{
  "dependencies": {
    "local": "workspace:*",
    "rel": "file:../lib",
    "ok": "1.0.0"
  }
}"#;
        let packages = parse_package_json(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "ok");
    }

    #[test]
    fn parse_package_json_with_meta_reads_package_manager() {
        let content = r#"{
  "name": "app",
  "packageManager": "pnpm@9.0.0",
  "dependencies": {}
}"#;
        let (_, meta) = parse_package_json_with_meta(content).unwrap();
        assert_eq!(meta.package_manager.as_deref(), Some("pnpm@9.0.0"));
        assert_eq!(meta.name.as_deref(), Some("app"));
    }

    #[test]
    fn is_registry_dependency_spec_filters_protocols() {
        assert!(is_registry_dependency_spec("^1.0.0"));
        assert!(is_registry_dependency_spec("1.2.3"));
        assert!(!is_registry_dependency_spec("workspace:*"));
        assert!(!is_registry_dependency_spec("file:../x"));
        assert!(!is_registry_dependency_spec(
            "git+https://example.com/r.git"
        ));
        assert!(!is_registry_dependency_spec("https://example.com/t.tgz"));
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        assert!(parse_package_json("{").is_err());
    }
}
