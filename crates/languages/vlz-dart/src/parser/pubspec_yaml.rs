// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use serde_norway::Value;
use vlz_db::{
    DeclarationKind, PUB_ECOSYSTEM, PUBSPEC_MANIFEST_FILE_NAME, Package,
};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::pubspec_lock::{
    is_pub_dev_hosted_url, is_pub_package_name, scalar_to_string,
};

/// Manifest sections whose entries are scanned (`dependency_overrides` is
/// intentionally excluded; the lock is authoritative for versions).
const SCANNED_SECTIONS: &[&str] = &["dependencies", "dev_dependencies"];

/// Constraint recorded for a dependency declared without a version.
const ANY_CONSTRAINT: &str = "any";

/// Dependency keys that mark a non-registry source.
const NON_REGISTRY_KEYS: &[&str] = &["sdk", "git", "path"];

/// Parse `pubspec.yaml` content into direct dependency packages.
pub fn parse_pubspec_yaml(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_pubspec_yaml_with_declarations(
        content,
        Path::new(PUBSPEC_MANIFEST_FILE_NAME),
    )?
    .0)
}

/// Parse with declaration line metadata (FR-036a).
///
/// Only registry dependencies on the default pub.dev host are returned;
/// `sdk`, `git`, `path` and custom hosted dependencies are skipped.
pub fn parse_pubspec_yaml_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let doc: Value = serde_norway::from_str(content).map_err(|e| {
        ParserError::Parse(format!("pubspec.yaml parse error: {e}"))
    })?;
    let lines = dependency_lines(content);
    let mut parsed = Vec::new();
    for section in SCANNED_SECTIONS {
        let Some(deps) = doc.get(*section).and_then(Value::as_mapping) else {
            continue;
        };
        for (key, spec) in deps {
            let Some(key) = key.as_str() else {
                continue;
            };
            let Some((name, version)) = registry_dependency(key, spec) else {
                continue;
            };
            parsed.push(ParsedDependency {
                package: Package {
                    name,
                    version,
                    ecosystem: Some(PUB_ECOSYSTEM.to_string()),
                    ..Default::default()
                },
                path: path.to_path_buf(),
                start_line: lines.get(key).copied().unwrap_or(1),
                end_line: None,
                kind: DeclarationKind::Manifest,
            });
        }
    }
    let packages = parsed.iter().map(|p| p.package.clone()).collect();
    Ok((packages, parsed))
}

/// Resolve a dependency entry to `(package name, constraint)` when it is a
/// default pub.dev registry dependency.
fn registry_dependency(key: &str, spec: &Value) -> Option<(String, String)> {
    match spec {
        Value::Null => {
            valid_name(key).map(|n| (n, ANY_CONSTRAINT.to_string()))
        }
        Value::String(constraint) => {
            valid_name(key).map(|n| (n, constraint.clone()))
        }
        Value::Mapping(_) => {
            if NON_REGISTRY_KEYS.iter().any(|k| spec.get(*k).is_some()) {
                return None;
            }
            let mut name = key.to_string();
            if let Some(hosted) = spec.get("hosted") {
                let url = hosted
                    .as_str()
                    .or_else(|| hosted.get("url").and_then(Value::as_str))?;
                if !is_pub_dev_hosted_url(url) {
                    return None;
                }
                if let Some(real) = hosted.get("name").and_then(Value::as_str)
                {
                    name = real.to_string();
                }
            }
            let version = spec
                .get("version")
                .and_then(scalar_to_string)
                .unwrap_or_else(|| ANY_CONSTRAINT.to_string());
            valid_name(&name).map(|n| (n, version))
        }
        _ => None,
    }
}

fn valid_name(name: &str) -> Option<String> {
    is_pub_package_name(name).then(|| name.to_string())
}

/// Map of dependency key -> 1-based line within the scanned sections.
fn dependency_lines(content: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let mut in_section = false;
    let mut entry_indent: Option<usize> = None;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            in_section = trimmed
                .strip_suffix(':')
                .is_some_and(|key| SCANNED_SECTIONS.contains(&key));
            entry_indent = None;
            continue;
        }
        if !in_section {
            continue;
        }
        let expected = *entry_indent.get_or_insert(indent);
        if indent != expected {
            continue;
        }
        if let Some((key, _)) = trimmed.split_once(':') {
            let key = key.trim_matches(|c| c == '"' || c == '\'');
            out.entry(key.to_string()).or_insert(index as u32 + 1);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use vlz_db::{DeclarationKind, PUB_ECOSYSTEM};

    const SAMPLE: &str = r#"name: app
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  flutter:
    sdk: flutter
  http: ^1.0.0
  anything:
  local_pkg:
    path: ../local_pkg
  git_pkg:
    git: https://example.test/git_pkg.git
  private_pkg:
    hosted: https://pub.internal.example
    version: ^2.0.0
  explicit_pub:
    hosted:
      name: explicit_pub
      url: https://pub.dev
    version: ^3.1.0
dev_dependencies:
  test: ^1.24.0
dependency_overrides:
  http: 1.2.0
"#;

    fn names(pkgs: &[vlz_db::Package]) -> Vec<&str> {
        pkgs.iter().map(|p| p.name.as_str()).collect()
    }

    #[test]
    fn collects_registry_dependencies_and_dev_dependencies() {
        let pkgs = parse_pubspec_yaml(SAMPLE).unwrap();
        assert_eq!(
            names(&pkgs),
            vec!["http", "anything", "explicit_pub", "test"]
        );
        assert!(
            pkgs.iter()
                .all(|p| p.ecosystem.as_deref() == Some(PUB_ECOSYSTEM))
        );
        assert_eq!(pkgs[0].version, "^1.0.0");
        assert_eq!(pkgs[1].version, "any");
        assert_eq!(pkgs[2].version, "^3.1.0");
    }

    #[test]
    fn dependency_overrides_are_not_packages() {
        let (pkgs, parsed) = parse_pubspec_yaml_with_declarations(
            SAMPLE,
            Path::new("pubspec.yaml"),
        )
        .unwrap();
        assert_eq!(pkgs.iter().filter(|p| p.name == "http").count(), 1);
        assert_eq!(parsed.len(), pkgs.len());
    }

    #[test]
    fn declarations_are_manifest_kind_with_line_numbers() {
        let (_, parsed) = parse_pubspec_yaml_with_declarations(
            SAMPLE,
            Path::new("pubspec.yaml"),
        )
        .unwrap();
        assert!(parsed.iter().all(|d| d.kind == DeclarationKind::Manifest));
        let http = parsed.iter().find(|d| d.package.name == "http").unwrap();
        assert_eq!(http.start_line, 7);
        let test = parsed.iter().find(|d| d.package.name == "test").unwrap();
        assert_eq!(test.start_line, 22);
    }

    #[test]
    fn empty_and_missing_sections_are_empty() {
        assert!(parse_pubspec_yaml("").unwrap().is_empty());
        assert!(parse_pubspec_yaml("name: app\n").unwrap().is_empty());
    }

    #[test]
    fn malformed_yaml_is_parse_error() {
        let err = parse_pubspec_yaml("dependencies: [unclosed").unwrap_err();
        assert!(matches!(err, ParserError::Parse(_)));
    }

    #[test]
    fn invalid_package_names_are_skipped() {
        let pkgs =
            parse_pubspec_yaml("dependencies:\n  Bad-Name: ^1.0.0\n").unwrap();
        assert!(pkgs.is_empty());
    }

    #[test]
    fn unexpected_value_types_are_skipped() {
        let content = "dependencies:\n  weird: [1, 2]\n  num: 5\n";
        assert!(parse_pubspec_yaml(content).unwrap().is_empty());
    }
}
