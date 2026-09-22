// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use vlz_db::{DeclarationKind, NUGET_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

/// NuGet `packages.lock.json` entry under a target framework.
#[derive(Debug, Deserialize)]
struct LockPackageEntry {
    #[serde(rename = "type", default)]
    entry_type: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
}

/// Top-level `packages.lock.json` document.
#[derive(Debug, Deserialize)]
struct PackagesLockFile {
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, LockPackageEntry>>,
}

/// Parse `packages.lock.json` content into pinned NuGet packages.
pub fn parse_packages_lock(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_packages_lock_with_declarations(
        content,
        Path::new("packages.lock.json"),
    )?
    .0)
}

/// Parse with declaration metadata (FR-036a).
pub fn parse_packages_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let value: Value = serde_json::from_str(content).map_err(|e| {
        ParserError::Parse(format!("packages.lock.json parse error: {e}"))
    })?;
    let lock: PackagesLockFile =
        serde_json::from_value(value).map_err(|e| {
            ParserError::Parse(format!(
                "packages.lock.json structure error: {e}"
            ))
        })?;

    let mut packages = Vec::new();
    let mut seen = HashSet::new();
    for framework_deps in lock.dependencies.values() {
        for (name, entry) in framework_deps {
            if !is_nuget_package_name(name) {
                continue;
            }
            if is_project_or_path_only(entry) {
                continue;
            }
            let Some(version) = entry.resolved.as_deref() else {
                continue;
            };
            let version = normalize_nuget_version(version);
            if version.is_empty() {
                continue;
            }
            let pkg = Package {
                name: name.to_string(),
                version,
                ecosystem: Some(NUGET_ECOSYSTEM.to_string()),
            };
            if seen.insert((pkg.name.clone(), pkg.version.clone())) {
                packages.push(pkg);
            }
        }
    }

    let line_map = name_resolved_lines(content);
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

/// True when `name` looks like a NuGet package identity (not empty).
pub fn is_nuget_package_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
}

fn is_project_or_path_only(entry: &LockPackageEntry) -> bool {
    let Some(entry_type) = entry.entry_type.as_deref() else {
        return false;
    };
    let lower = entry_type.to_ascii_lowercase();
    matches!(lower.as_str(), "project" | "path")
}

pub(crate) fn normalize_nuget_version(version: &str) -> String {
    version.trim().to_string()
}

fn name_resolved_lines(content: &str) -> BTreeMap<(String, String), u32> {
    let mut out = BTreeMap::new();
    let mut pending_name: Option<String> = None;
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Package key line: "Package.Name": {
        if trimmed.ends_with('{')
            && let Some(rest) = trimmed.strip_prefix('"')
            && let Some(end) = rest.find('"')
        {
            let name = &rest[..end];
            let after = &rest[end + 1..];
            if after.trim_start().starts_with(':')
                && is_nuget_package_name(name)
                && !name.eq_ignore_ascii_case("dependencies")
                && !name.eq_ignore_ascii_case("version")
                && !name.eq_ignore_ascii_case("type")
                && !name.eq_ignore_ascii_case("resolved")
                && !name.eq_ignore_ascii_case("requested")
                && !name.eq_ignore_ascii_case("contentHash")
            {
                pending_name = Some(name.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix('"')
            && let Some(end) = rest.find('"')
        {
            let key = &rest[..end];
            if key == "resolved"
                && let Some(name) = pending_name.take()
                && let Some(vstart) = value_start(trimmed)
            {
                let vend = trimmed[vstart..].find('"').map(|o| vstart + o);
                if let Some(vend) = vend {
                    let version =
                        normalize_nuget_version(&trimmed[vstart..vend]);
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
    fn parse_direct_and_transitive_across_frameworks() {
        let content = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc"
      },
      "System.Text.Json": {
        "type": "Transitive",
        "resolved": "8.0.0",
        "contentHash": "def"
      }
    },
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc"
      }
    }
  }
}"#;
        let packages = parse_packages_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| {
            p.name == "Newtonsoft.Json" && p.version == "13.0.3"
        }));
        assert!(packages.iter().any(|p| {
            p.name == "System.Text.Json" && p.version == "8.0.0"
        }));
        assert!(
            packages
                .iter()
                .all(|p| p.ecosystem.as_deref() == Some(NUGET_ECOSYSTEM))
        );
    }

    #[test]
    fn skips_project_and_path_entries() {
        let content = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Demo.Lib": {
        "type": "Project"
      },
      "Local.Pkg": {
        "type": "Path",
        "resolved": "1.0.0"
      },
      "Ok.Pkg": {
        "type": "Direct",
        "resolved": "2.0.0"
      }
    }
  }
}"#;
        let packages = parse_packages_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Ok.Pkg");
    }

    #[test]
    fn skips_entries_without_resolved() {
        let content = r#"{
  "dependencies": {
    "net8.0": {
      "Missing.Ver": {
        "type": "Direct"
      },
      "Has.Ver": {
        "type": "Transitive",
        "resolved": "1.2.3"
      }
    }
  }
}"#;
        let packages = parse_packages_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Has.Ver");
    }

    #[test]
    fn parse_packages_lock_invalid_json_errors() {
        let err = parse_packages_lock("{").unwrap_err();
        assert!(err.to_string().contains("packages.lock.json"));
    }

    #[test]
    fn parse_packages_lock_structure_error() {
        let err = parse_packages_lock(r#"{"dependencies":1}"#).unwrap_err();
        assert!(err.to_string().contains("structure"));
    }

    #[test]
    fn parse_packages_lock_with_declarations_sets_lines() {
        let content = r#"{
  "dependencies": {
    "net8.0": {
      "Cli.Contract": {
        "type": "Direct",
        "resolved": "1.0.0"
      }
    }
  }
}"#;
        let (packages, parsed) = parse_packages_lock_with_declarations(
            content,
            Path::new("packages.lock.json"),
        )
        .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].start_line >= 1);
        assert_eq!(parsed[0].kind, DeclarationKind::Lockfile);
    }

    #[test]
    fn empty_dependencies_yields_empty_packages() {
        let content = r#"{"version":1,"dependencies":{}}"#;
        let packages = parse_packages_lock(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn is_nuget_package_name_rejects_empty() {
        assert!(is_nuget_package_name("Newtonsoft.Json"));
        assert!(!is_nuget_package_name(""));
        assert!(!is_nuget_package_name("   "));
    }

    #[test]
    fn skips_blank_names_empty_versions_and_typeless_entries() {
        // Compact `:"` form exercises value_start's no-space arm.
        let content = r#"{
  "dependencies": {
    "net8.0": {
      "": {
        "type": "Direct",
        "resolved": "1.0.0"
      },
      "Blank.Ver": {
        "type": "Direct",
        "resolved": "   "
      },
      "No.Type": {
        "resolved":"2.0.0"
      }
    }
  }
}"#;
        let packages = parse_packages_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "No.Type");
        assert_eq!(packages[0].version, "2.0.0");
    }

    #[test]
    fn declaration_line_falls_back_when_resolved_key_missing() {
        // Package present in JSON object form that name_resolved_lines may
        // not pair; still returns a declaration with a default line.
        let content = r#"{"dependencies":{"net8.0":{"Fallback.Pkg":{"type":"Direct","resolved":"9.9.9"}}}}"#;
        let (packages, parsed) = parse_packages_lock_with_declarations(
            content,
            Path::new("packages.lock.json"),
        )
        .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].start_line >= 1);
    }
}
