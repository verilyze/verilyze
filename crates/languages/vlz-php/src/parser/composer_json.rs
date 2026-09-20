// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use vlz_db::{DeclarationKind, PACKAGIST_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

#[derive(Debug, Deserialize)]
struct ComposerJsonFile {
    require: Option<BTreeMap<String, String>>,
    #[serde(rename = "require-dev")]
    require_dev: Option<BTreeMap<String, String>>,
}

/// True when `name` is a Packagist-style `vendor/package` identity.
///
/// Platform packages (`php`, `ext-*`, `lib-*`, and similar) are excluded.
pub fn is_packagist_package_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "php"
        || lower == "hhvm"
        || lower.starts_with("ext-")
        || lower.starts_with("lib-")
        || lower.starts_with("composer-")
    {
        return false;
    }
    // Packagist packages always use vendor/package.
    let Some((vendor, package)) = trimmed.split_once('/') else {
        return false;
    };
    !vendor.is_empty() && !package.is_empty() && !package.contains('/')
}

/// Parse composer.json content into direct dependency packages.
pub fn parse_composer_json(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_composer_json_with_declarations(
        content,
        Path::new("composer.json"),
    )?
    .0)
}

/// Parse composer.json with declaration line metadata (FR-036a).
pub fn parse_composer_json_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let file: ComposerJsonFile =
        serde_json::from_str(content).map_err(|e| {
            ParserError::Parse(format!("composer.json parse error: {e}"))
        })?;

    let mut parsed = Vec::new();
    let line_map = dependency_name_lines(content);
    for map in [file.require.as_ref(), file.require_dev.as_ref()] {
        let Some(deps) = map else {
            continue;
        };
        for (name, spec) in deps {
            if !is_packagist_package_name(name) {
                continue;
            }
            if is_non_registry_constraint(spec) {
                continue;
            }
            let start_line = line_map.get(name.as_str()).copied().unwrap_or(1);
            parsed.push(ParsedDependency {
                package: Package {
                    name: name.clone(),
                    // Ranges are not OSV-ready; resolver prefers lock pins.
                    version: spec.clone(),
                    ecosystem: Some(PACKAGIST_ECOSYSTEM.to_string()),
                },
                path: path.to_path_buf(),
                start_line,
                end_line: None,
                kind: DeclarationKind::Manifest,
            });
        }
    }
    let packages = parsed.iter().map(|p| p.package.clone()).collect();
    Ok((packages, parsed))
}

fn is_non_registry_constraint(spec: &str) -> bool {
    let s = spec.trim();
    if s.is_empty() {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    lower.starts_with("path:")
        || lower.starts_with("vcs:")
        || lower.starts_with("git:")
        || lower.starts_with("git@")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ssh://")
}

/// Best-effort map of dependency name -> line number in composer.json text.
fn dependency_name_lines(content: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('"')
            && let Some(end) = rest.find('"')
        {
            let name = &rest[..end];
            let after = &rest[end + 1..];
            if after.trim_start().starts_with(':')
                && is_packagist_package_name(name)
            {
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
    fn parse_require_and_require_dev() {
        let content = r#"{
  "name": "app/demo",
  "require": {
    "php": ">=8.1",
    "symfony/http-foundation": "^6.4"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0",
    "ext-json": "*"
  }
}"#;
        let packages = parse_composer_json(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "symfony/http-foundation"));
        assert!(packages.iter().any(|p| p.name == "phpunit/phpunit"));
        assert!(!packages.iter().any(|p| p.name == "php"));
        assert!(
            packages
                .iter()
                .all(|p| p.ecosystem.as_deref() == Some(PACKAGIST_ECOSYSTEM))
        );
    }

    #[test]
    fn skips_path_and_vcs_constraints() {
        let content = r#"{
  "require": {
    "local/pkg": "path:../local",
    "remote/pkg": "git@github.com:org/repo.git",
    "ok/pkg": "^1.0"
  }
}"#;
        let packages = parse_composer_json(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "ok/pkg");
    }

    #[test]
    fn is_packagist_package_name_filters_platform() {
        assert!(is_packagist_package_name("vendor/pkg"));
        assert!(!is_packagist_package_name("php"));
        assert!(!is_packagist_package_name("ext-mbstring"));
        assert!(!is_packagist_package_name("lib-curl"));
        assert!(!is_packagist_package_name("composer-plugin-api"));
        assert!(!is_packagist_package_name("nodashes"));
        assert!(!is_packagist_package_name(""));
        assert!(!is_packagist_package_name("a/b/c"));
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        assert!(parse_composer_json("{").is_err());
    }

    #[test]
    fn declarations_include_line_numbers() {
        let content = "{\n  \"require\": {\n    \"a/b\": \"1.0\"\n  }\n}\n";
        let (_, parsed) = parse_composer_json_with_declarations(
            content,
            Path::new("composer.json"),
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].start_line, 3);
    }
}
