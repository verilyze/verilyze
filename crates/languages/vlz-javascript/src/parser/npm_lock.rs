// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use vlz_db::{DeclarationKind, NPM_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

#[derive(Debug, Deserialize)]
struct NpmLockFile {
    #[serde(default)]
    packages: BTreeMap<String, NpmLockPackage>,
    /// lockfileVersion 1 style
    #[serde(default)]
    dependencies: BTreeMap<String, NpmLockV1Dep>,
}

#[derive(Debug, Deserialize)]
struct NpmLockPackage {
    version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    resolved: Option<String>,
    #[serde(default)]
    link: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct NpmLockV1Dep {
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmLockV1Dep>,
}

/// Parse npm `package-lock.json` or `npm-shrinkwrap.json` content.
pub fn parse_npm_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_npm_lock_with_declarations(
        content,
        Path::new("package-lock.json"),
    )?
    .0)
}

/// Parse with declaration metadata.
pub fn parse_npm_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let value: Value = serde_json::from_str(content).map_err(|e| {
        ParserError::Parse(format!("npm lock parse error: {e}"))
    })?;
    let lock: NpmLockFile =
        serde_json::from_value(value.clone()).map_err(|e| {
            ParserError::Parse(format!("npm lock structure error: {e}"))
        })?;

    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if !lock.packages.is_empty() {
        for (key, entry) in &lock.packages {
            if key.is_empty() {
                // Root package entry.
                continue;
            }
            if entry.link == Some(true) {
                continue;
            }
            let name = package_name_from_lock_key(key);
            let Some(version) = entry.version.as_deref() else {
                continue;
            };
            if !is_usable_npm_version(version) {
                continue;
            }
            let pkg = Package {
                name: name.to_string(),
                version: version.to_string(),
                ecosystem: Some(NPM_ECOSYSTEM.to_string()),
            };
            if seen.insert((pkg.name.clone(), pkg.version.clone())) {
                packages.push(pkg);
            }
        }
    } else {
        collect_v1_deps("", &lock.dependencies, &mut packages, &mut seen);
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

fn package_name_from_lock_key(key: &str) -> &str {
    // "node_modules/lodash" or "node_modules/@scope/pkg" or nested
    // "node_modules/a/node_modules/b"
    let trimmed = key.trim_start_matches("node_modules/");
    if let Some(idx) = trimmed.rfind("node_modules/") {
        &trimmed[idx + "node_modules/".len()..]
    } else {
        trimmed
    }
}

fn is_usable_npm_version(version: &str) -> bool {
    let v = version.trim();
    if v.is_empty() {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    !(lower.starts_with("file:")
        || lower.starts_with("workspace:")
        || lower.starts_with("link:")
        || lower.starts_with("npm:"))
}

fn collect_v1_deps(
    _parent: &str,
    deps: &BTreeMap<String, NpmLockV1Dep>,
    out: &mut Vec<Package>,
    seen: &mut std::collections::HashSet<(String, String)>,
) {
    for (name, dep) in deps {
        if let Some(version) = dep.version.as_deref()
            && is_usable_npm_version(version)
        {
            let pkg = Package {
                name: name.clone(),
                version: version.to_string(),
                ecosystem: Some(NPM_ECOSYSTEM.to_string()),
            };
            if seen.insert((pkg.name.clone(), pkg.version.clone())) {
                out.push(pkg);
            }
        }
        collect_v1_deps(name, &dep.dependencies, out, seen);
    }
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
            if key.starts_with("node_modules/") || !key.contains('/') {
                // package key or top-level dep name in v1
                if key.starts_with("node_modules/") {
                    pending_name =
                        Some(package_name_from_lock_key(key).to_string());
                } else if key != "version"
                    && key != "resolved"
                    && key != "integrity"
                    && key != "requires"
                    && key != "dependencies"
                    && key != "packages"
                    && key != "lockfileVersion"
                    && key != "name"
                    && key != "requires"
                {
                    pending_name = Some(key.to_string());
                }
            }
            if key == "version"
                && let Some(name) = pending_name.take()
            {
                // "version": "1.2.3"
                if let Some(vstart) = trimmed
                    .find(": \"")
                    .or_else(|| trimmed.find(":\""))
                    .map(|p| {
                        if trimmed[p..].starts_with(": \"") {
                            p + 3
                        } else {
                            p + 2
                        }
                    })
                {
                    let vend = trimmed[vstart..].find('"').map(|o| vstart + o);
                    if let Some(vend) = vend {
                        let version = trimmed[vstart..vend].to_string();
                        out.insert((name.clone(), version), (i + 1) as u32);
                        out.entry((name, String::new()))
                            .or_insert((i + 1) as u32);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lockfile_v2_packages() {
        let content = r#"{
  "name": "app",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/@scope/pkg": { "version": "1.2.3" }
  }
}"#;
        let packages = parse_npm_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21")
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "@scope/pkg" && p.version == "1.2.3")
        );
    }

    #[test]
    fn parse_lockfile_v1_dependencies() {
        let content = r#"{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": {
      "version": "1.3.0",
      "dependencies": {
        "ms": { "version": "2.1.0" }
      }
    }
  }
}"#;
        let packages = parse_npm_lock(content).unwrap();
        assert!(packages.iter().any(|p| p.name == "left-pad"));
        assert!(packages.iter().any(|p| p.name == "ms"));
    }

    #[test]
    fn skips_link_entries() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/local": { "version": "1.0.0", "link": true },
    "node_modules/real": { "version": "2.0.0" }
  }
}"#;
        let packages = parse_npm_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "real");
    }

    #[test]
    fn skips_npm_alias_versions() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/foo": { "version": "npm:bar@1.2.3" },
    "node_modules/real": { "version": "2.0.0" }
  }
}"#;
        let packages = parse_npm_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "real");
        assert!(!packages.iter().any(|p| p.version.starts_with("npm:")));
    }

    #[test]
    fn package_name_from_nested_key() {
        assert_eq!(
            package_name_from_lock_key("node_modules/a/node_modules/b"),
            "b"
        );
        assert_eq!(package_name_from_lock_key("node_modules/@s/p"), "@s/p");
    }
}
