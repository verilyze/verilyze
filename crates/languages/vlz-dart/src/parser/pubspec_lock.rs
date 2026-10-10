// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::Deserialize;
use serde_norway::Value;
use vlz_db::{
    DeclarationKind, PUB_ECOSYSTEM, PUBSPEC_LOCK_FILE_NAME, Package,
};
use vlz_manifest_parser::{ParsedDependency, ParserError};

/// Default hosted-pub URLs whose package names match OSV `Pub` identities.
///
/// Custom hosted URLs are skipped so a private package cannot match a public
/// advisory with the same name (dependency confusion).
const PUB_DEV_HOSTED_URLS: &[&str] =
    &["https://pub.dev", "https://pub.dartlang.org"];

const SOURCE_HOSTED: &str = "hosted";

#[derive(Debug, Deserialize)]
struct PubspecLockFile {
    #[serde(default)]
    packages: BTreeMap<String, LockEntry>,
}

#[derive(Debug, Deserialize)]
struct LockEntry {
    source: Option<String>,
    version: Option<Value>,
    description: Option<Value>,
}

/// True when `url` is the default pub.dev host (case and trailing slash
/// insensitive; scheme must be `https`).
pub fn is_pub_dev_hosted_url(url: &str) -> bool {
    let normalized = url.trim().trim_end_matches('/').to_ascii_lowercase();
    PUB_DEV_HOSTED_URLS.contains(&normalized.as_str())
}

/// True when `name` is a valid pub package identifier (lowercase letters,
/// digits and underscores; must not start with a digit).
pub fn is_pub_package_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == '_')
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Render a scalar YAML value as a string (`None` for maps, lists, null).
pub(super) fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn hosted_on_pub_dev(entry: &LockEntry) -> bool {
    if entry.source.as_deref() != Some(SOURCE_HOSTED) {
        return false;
    }
    entry
        .description
        .as_ref()
        .and_then(|d| d.get("url"))
        .and_then(Value::as_str)
        .is_some_and(is_pub_dev_hosted_url)
}

/// Parse `pubspec.lock` content into pinned pub.dev packages.
pub fn parse_pubspec_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_pubspec_lock_with_declarations(
        content,
        Path::new(PUBSPEC_LOCK_FILE_NAME),
    )?
    .0)
}

/// Parse with declaration metadata (FR-036a).
///
/// Only `source: hosted` entries on the default pub.dev host are returned;
/// `git`, `path`, `sdk` and custom hosted entries are skipped with a stderr
/// warning.
pub fn parse_pubspec_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let lock: Option<PubspecLockFile> = serde_norway::from_str(content)
        .map_err(|e| {
            ParserError::Parse(format!("pubspec.lock parse error: {e}"))
        })?;
    let lock = lock.unwrap_or(PubspecLockFile {
        packages: BTreeMap::new(),
    });

    let lines = package_key_lines(content);
    let mut packages = Vec::new();
    let mut parsed = Vec::new();
    let mut seen = HashSet::new();
    for (name, entry) in &lock.packages {
        if !is_pub_package_name(name) {
            continue;
        }
        if !hosted_on_pub_dev(entry) {
            if entry.source.as_deref() != Some("sdk") {
                eprintln!(
                    "vlz warning: skipping {name} in {}: source is not the default pub.dev host (no OSV Pub identity)",
                    path.display()
                );
            }
            continue;
        }
        let Some(version) = entry.version.as_ref().and_then(scalar_to_string)
        else {
            continue;
        };
        if version.trim().is_empty() {
            continue;
        }
        let pkg = Package {
            name: name.clone(),
            version,
            ecosystem: Some(PUB_ECOSYSTEM.to_string()),
            ..Default::default()
        };
        if !seen.insert((pkg.name.clone(), pkg.version.clone())) {
            continue;
        }
        parsed.push(ParsedDependency {
            package: pkg.clone(),
            path: path.to_path_buf(),
            start_line: lines.get(name.as_str()).copied().unwrap_or(1),
            end_line: None,
            kind: DeclarationKind::Lockfile,
        });
        packages.push(pkg);
    }
    Ok((packages, parsed))
}

/// Map of package key -> 1-based line within the top-level `packages:` map.
fn package_key_lines(content: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let mut in_packages = false;
    for (index, line) in content.lines().enumerate() {
        if !line.starts_with(' ') && !line.starts_with('#') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(' ') {
            continue;
        }
        if let Some(key) = rest.trim_end().strip_suffix(':') {
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

    const SAMPLE_LOCK: &str = r#"# Generated by pub
packages:
  async:
    dependency: transitive
    description:
      name: async
      sha256: "deadbeef"
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "cafe"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.2"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  local_pkg:
    dependency: "direct main"
    description:
      path: "../local_pkg"
      relative: true
    source: path
    version: "1.0.0"
  git_pkg:
    dependency: "direct main"
    description:
      path: "."
      ref: main
      resolved-ref: abc
      url: "https://example.test/git_pkg.git"
    source: git
    version: "0.1.0"
  private_pkg:
    dependency: "direct main"
    description:
      name: private_pkg
      url: "https://pub.internal.example"
    source: hosted
    version: "3.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"#;

    #[test]
    fn keeps_only_pub_dev_hosted_packages() {
        let pkgs = parse_pubspec_lock(SAMPLE_LOCK).unwrap();
        let names: Vec<_> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["async", "http"]);
        assert!(
            pkgs.iter()
                .all(|p| p.ecosystem.as_deref() == Some(PUB_ECOSYSTEM))
        );
        assert_eq!(pkgs[1].version, "1.2.2");
    }

    #[test]
    fn declarations_are_lockfile_kind_with_line_numbers() {
        let (pkgs, parsed) = parse_pubspec_lock_with_declarations(
            SAMPLE_LOCK,
            Path::new("pubspec.lock"),
        )
        .unwrap();
        assert_eq!(pkgs.len(), parsed.len());
        assert!(parsed.iter().all(|d| d.kind == DeclarationKind::Lockfile));
        let http = parsed.iter().find(|d| d.package.name == "http").unwrap();
        let line = SAMPLE_LOCK
            .lines()
            .position(|l| l == "  http:")
            .map(|i| i as u32 + 1)
            .unwrap();
        assert_eq!(http.start_line, line);
    }

    #[test]
    fn empty_or_blank_content_is_empty_lock() {
        assert!(parse_pubspec_lock("").unwrap().is_empty());
        assert!(parse_pubspec_lock("  \n").unwrap().is_empty());
    }

    #[test]
    fn missing_packages_key_is_empty_lock() {
        let pkgs = parse_pubspec_lock("sdks:\n  dart: \">=3.0.0\"\n").unwrap();
        assert!(pkgs.is_empty());
    }

    #[test]
    fn entries_without_version_or_valid_name_are_skipped() {
        let content = r#"packages:
  nover:
    description:
      name: nover
      url: "https://pub.dev"
    source: hosted
  BadName:
    description:
      name: BadName
      url: "https://pub.dev"
    source: hosted
    version: "1.0.0"
  nourl:
    description:
      name: nourl
    source: hosted
    version: "1.0.0"
"#;
        assert!(parse_pubspec_lock(content).unwrap().is_empty());
    }

    #[test]
    fn legacy_pub_dartlang_org_url_is_default_host() {
        let content = r#"packages:
  old:
    description:
      name: old
      url: "https://pub.dartlang.org"
    source: hosted
    version: "1.0.0"
"#;
        assert_eq!(parse_pubspec_lock(content).unwrap().len(), 1);
    }

    #[test]
    fn malformed_yaml_is_parse_error() {
        let err = parse_pubspec_lock("packages: [unclosed").unwrap_err();
        assert!(matches!(err, ParserError::Parse(_)));
    }

    #[test]
    fn pub_dev_url_matching_ignores_trailing_slash_and_case() {
        assert!(is_pub_dev_hosted_url("https://pub.dev"));
        assert!(is_pub_dev_hosted_url("https://pub.dev/"));
        assert!(is_pub_dev_hosted_url("HTTPS://PUB.DEV"));
        assert!(!is_pub_dev_hosted_url("https://pub.dev.evil.example"));
        assert!(!is_pub_dev_hosted_url("http://pub.dev"));
        assert!(!is_pub_dev_hosted_url(""));
    }

    #[test]
    fn package_name_rules() {
        assert!(is_pub_package_name("http"));
        assert!(is_pub_package_name("flutter_test"));
        assert!(is_pub_package_name("_private1"));
        assert!(!is_pub_package_name(""));
        assert!(!is_pub_package_name("Http"));
        assert!(!is_pub_package_name("a-b"));
        assert!(!is_pub_package_name("1abc"));
    }
}
