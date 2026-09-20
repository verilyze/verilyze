// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use vlz_db::{DeclarationKind, PACKAGIST_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::composer_json::is_packagist_package_name;

#[derive(Debug, Deserialize)]
struct ComposerLockFile {
    #[serde(default)]
    packages: Vec<ComposerLockPackage>,
    #[serde(rename = "packages-dev", default)]
    packages_dev: Vec<ComposerLockPackage>,
}

#[derive(Debug, Deserialize)]
struct ComposerLockPackage {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    dist: Option<ComposerDist>,
    #[serde(default)]
    source: Option<ComposerSource>,
}

#[derive(Debug, Deserialize)]
struct ComposerDist {
    #[serde(rename = "type")]
    dist_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ComposerSource {
    #[serde(rename = "type")]
    source_type: Option<String>,
}

/// Parse `composer.lock` content into pinned packages.
pub fn parse_composer_lock(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_composer_lock_with_declarations(
        content,
        Path::new("composer.lock"),
    )?
    .0)
}

/// Parse with declaration metadata (FR-036a).
pub fn parse_composer_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let value: Value = serde_json::from_str(content).map_err(|e| {
        ParserError::Parse(format!("composer.lock parse error: {e}"))
    })?;
    let lock: ComposerLockFile =
        serde_json::from_value(value).map_err(|e| {
            ParserError::Parse(format!("composer.lock structure error: {e}"))
        })?;

    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in lock.packages.iter().chain(lock.packages_dev.iter()) {
        let Some(name) = entry.name.as_deref() else {
            continue;
        };
        if !is_packagist_package_name(name) {
            continue;
        }
        if is_path_or_vcs_only(entry) {
            continue;
        }
        let Some(version) = entry.version.as_deref() else {
            continue;
        };
        let version = normalize_composer_version(version);
        if version.is_empty() {
            continue;
        }
        let pkg = Package {
            name: name.to_string(),
            version,
            ecosystem: Some(PACKAGIST_ECOSYSTEM.to_string()),
        };
        if seen.insert((pkg.name.clone(), pkg.version.clone())) {
            packages.push(pkg);
        }
    }

    let line_map = name_version_lines(content);
    let parsed: Vec<ParsedDependency> = packages
        .iter()
        .map(|pkg| {
            let start_line = line_map
                .get(&(pkg.name.clone(), pkg.version.clone()))
                .or_else(|| line_map.get(&(pkg.name.clone(), String::new())))
                .copied()
                .unwrap_or(1);
            ParsedDependency {
                package: pkg.clone(),
                path: path.to_path_buf(),
                start_line,
                end_line: None,
                kind: DeclarationKind::Lockfile,
            }
        })
        .collect();
    Ok((packages, parsed))
}

fn is_path_or_vcs_only(entry: &ComposerLockPackage) -> bool {
    if let Some(dist) = entry.dist.as_ref()
        && let Some(dist_type) = dist.dist_type.as_deref()
    {
        let lower = dist_type.to_ascii_lowercase();
        if lower == "path" {
            return true;
        }
    }
    // Skip VCS-only installs without a Packagist dist (path/vcs local forks).
    let has_dist = entry
        .dist
        .as_ref()
        .and_then(|d| d.dist_type.as_deref())
        .is_some_and(|t| {
            let lower = t.to_ascii_lowercase();
            lower != "path"
        });
    if has_dist {
        return false;
    }
    if let Some(source) = entry.source.as_ref()
        && let Some(source_type) = source.source_type.as_deref()
    {
        let lower = source_type.to_ascii_lowercase();
        return matches!(
            lower.as_str(),
            "path" | "vcs" | "git" | "svn" | "hg" | "fossil"
        );
    }
    false
}

fn normalize_composer_version(version: &str) -> String {
    let trimmed = version.trim();
    trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed)
        .to_string()
}

fn name_version_lines(content: &str) -> BTreeMap<(String, String), u32> {
    let mut out = BTreeMap::new();
    let mut pending_name: Option<String> = None;
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('"')
            && let Some(end) = rest.find('"')
        {
            let key = &rest[..end];
            let after = &rest[end + 1..];
            if !after.trim_start().starts_with(':') {
                continue;
            }
            if key == "name" {
                if let Some(vstart) = value_start(trimmed) {
                    let vend = trimmed[vstart..].find('"').map(|o| vstart + o);
                    if let Some(vend) = vend {
                        let name = &trimmed[vstart..vend];
                        if is_packagist_package_name(name) {
                            pending_name = Some(name.to_string());
                        }
                    }
                }
            } else if key == "version"
                && let Some(name) = pending_name.take()
                && let Some(vstart) = value_start(trimmed)
            {
                let vend = trimmed[vstart..].find('"').map(|o| vstart + o);
                if let Some(vend) = vend {
                    let version =
                        normalize_composer_version(&trimmed[vstart..vend]);
                    out.insert((name.clone(), version), (i + 1) as u32);
                    out.entry((name, String::new())).or_insert((i + 1) as u32);
                }
            }
        }
    }
    out
}

fn value_start(trimmed: &str) -> Option<usize> {
    trimmed
        .find(": \"")
        .map(|p| p + 3)
        .or_else(|| trimmed.find(":\"").map(|p| p + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_packages_and_packages_dev() {
        let content = r#"{
  "packages": [
    {
      "name": "symfony/http-foundation",
      "version": "v6.4.0",
      "dist": { "type": "zip", "url": "https://example.test/a.zip" }
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "10.5.0",
      "dist": { "type": "zip", "url": "https://example.test/b.zip" }
    }
  ]
}"#;
        let packages = parse_composer_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| {
            p.name == "symfony/http-foundation" && p.version == "6.4.0"
        }));
        assert!(
            packages
                .iter()
                .any(|p| p.name == "phpunit/phpunit" && p.version == "10.5.0")
        );
    }

    #[test]
    fn skips_path_and_vcs_only_and_platform() {
        let content = r#"{
  "packages": [
    {
      "name": "local/pkg",
      "version": "1.0.0",
      "dist": { "type": "path", "url": "../local" }
    },
    {
      "name": "fork/pkg",
      "version": "dev-main",
      "source": { "type": "git", "url": "https://example.test/x.git" }
    },
    {
      "name": "php",
      "version": "8.2.0"
    },
    {
      "name": "ok/pkg",
      "version": "2.0.0",
      "dist": { "type": "zip", "url": "https://example.test/ok.zip" }
    }
  ]
}"#;
        let packages = parse_composer_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "ok/pkg");
    }

    #[test]
    fn parse_composer_lock_invalid_json_errors() {
        let err = parse_composer_lock("{").unwrap_err();
        assert!(err.to_string().contains("composer.lock"));
    }

    #[test]
    fn parse_composer_lock_structure_error() {
        let err = parse_composer_lock(r#"{"packages":1}"#).unwrap_err();
        assert!(err.to_string().contains("structure"));
    }

    #[test]
    fn skips_entries_without_version() {
        let content = r#"{
  "packages": [
    { "name": "a/b", "dist": { "type": "zip" } },
    {
      "name": "c/d",
      "version": "1.0.0",
      "dist": { "type": "zip" }
    }
  ]
}"#;
        let packages = parse_composer_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "c/d");
    }

    #[test]
    fn parse_composer_lock_with_declarations_sets_lines() {
        let content = r#"{
  "packages": [
    {
      "name": "cli/contract",
      "version": "1.0.0",
      "dist": { "type": "zip" }
    }
  ]
}"#;
        let (packages, parsed) = parse_composer_lock_with_declarations(
            content,
            Path::new("composer.lock"),
        )
        .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].start_line >= 1);
    }

    #[test]
    fn value_start_accepts_compact_colon() {
        let content = r#"{"packages":[{"name":"a/b","version":"1.0.0","dist":{"type":"zip"}}]}"#;
        let (packages, parsed) = parse_composer_lock_with_declarations(
            content,
            Path::new("composer.lock"),
        )
        .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "a/b");
        assert_eq!(packages[0].version, "1.0.0");
        assert!(parsed[0].start_line >= 1);
    }

    #[test]
    fn skips_entry_with_empty_normalized_version() {
        let content = r#"{
  "packages": [
    {
      "name": "a/b",
      "version": "v",
      "dist": { "type": "zip" }
    },
    {
      "name": "c/d",
      "version": "1.0.0",
      "dist": { "type": "zip" }
    }
  ]
}"#;
        let packages = parse_composer_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "c/d");
    }

    #[test]
    fn skips_entry_with_null_name() {
        let content = r#"{
  "packages": [
    {
      "version": "1.0.0",
      "dist": { "type": "zip" }
    },
    {
      "name": "ok/pkg",
      "version": "2.0.0",
      "dist": { "type": "zip" }
    }
  ]
}"#;
        let packages = parse_composer_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "ok/pkg");
    }
}
