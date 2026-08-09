// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use vlz_db::{DeclarationKind, NPM_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

#[derive(Debug, Deserialize)]
struct PnpmLockFile {
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackage>,
    /// pnpm v9 importers / snapshots may use different shapes; packages is enough.
    #[serde(default)]
    snapshots: BTreeMap<String, serde_norway::Value>,
}

#[derive(Debug, Deserialize)]
struct PnpmPackage {
    #[serde(default)]
    #[allow(dead_code)]
    resolution: Option<serde_norway::Value>,
    #[serde(default)]
    version: Option<String>,
}

/// Parse `pnpm-lock.yaml` (lockfileVersion 5.x / 6.x / 9.x packages map).
pub fn parse_pnpm_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_pnpm_lock_with_declarations(
        content,
        Path::new("pnpm-lock.yaml"),
    )?
    .0)
}

/// Parse with declaration metadata.
pub fn parse_pnpm_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let lock: PnpmLockFile = serde_norway::from_str(content).map_err(|e| {
        ParserError::Parse(format!("pnpm-lock.yaml parse error: {e}"))
    })?;

    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::new();

    for (key, entry) in &lock.packages {
        if let Some((name, version)) = parse_pnpm_package_key(key) {
            push_pkg(
                name,
                version,
                path,
                &mut packages,
                &mut seen,
                &mut parsed,
            );
            continue;
        }
        if let Some(version) = entry.version.as_deref()
            && let Some(name) = name_from_pnpm_key_fallback(key)
        {
            push_pkg(
                name,
                version,
                path,
                &mut packages,
                &mut seen,
                &mut parsed,
            );
        }
    }

    // lockfileVersion 9 may list packages only under snapshots keys like
    // "/lodash@4.17.21"
    for key in lock.snapshots.keys() {
        if let Some((name, version)) = parse_pnpm_package_key(key) {
            push_pkg(
                name,
                version,
                path,
                &mut packages,
                &mut seen,
                &mut parsed,
            );
        }
    }

    Ok((packages, parsed))
}

fn push_pkg(
    name: &str,
    version: &str,
    path: &Path,
    packages: &mut Vec<Package>,
    seen: &mut std::collections::HashSet<(String, String)>,
    parsed: &mut Vec<ParsedDependency>,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    if version.starts_with("link:") || version.starts_with("file:") {
        return;
    }
    let pkg = Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Some(NPM_ECOSYSTEM.to_string()),
    };
    if seen.insert((pkg.name.clone(), pkg.version.clone())) {
        parsed.push(ParsedDependency {
            package: pkg.clone(),
            path: path.to_path_buf(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        });
        packages.push(pkg);
    }
}

/// Parse keys like `/lodash/4.17.21`, `/lodash@4.17.21`,
/// `/@scope/pkg/1.0.0`, `/@scope/pkg@1.0.0`.
fn parse_pnpm_package_key(key: &str) -> Option<(&str, &str)> {
    let key = key.trim().trim_start_matches('/');
    if key.is_empty() {
        return None;
    }
    // Peer suffix: /foo@1.0.0(bar@2.0.0) -> strip peers
    let key = key.split('(').next().unwrap_or(key);

    if let Some(rest) = key.strip_prefix('@') {
        // @scope/name@version or @scope/name/version
        let slash = rest.find('/')?;
        let after = &rest[slash + 1..];
        if let Some(at) = after.find('@') {
            let name_end = 1 + slash + 1 + at;
            let name = &key[..name_end];
            let version = &key[name_end + 1..];
            return Some((name, version));
        }
        // @scope/name/version
        if let Some(vslash) = after.rfind('/') {
            let name = &key[..1 + slash + 1 + vslash];
            let version = &after[vslash + 1..];
            return Some((name, version));
        }
        return None;
    }

    if let Some(at) = key.find('@') {
        return Some((&key[..at], &key[at + 1..]));
    }
    if let Some(slash) = key.find('/') {
        return Some((&key[..slash], &key[slash + 1..]));
    }
    None
}

fn name_from_pnpm_key_fallback(key: &str) -> Option<&str> {
    parse_pnpm_package_key(key).map(|(n, _)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pnpm_v6_style() {
        let content = r#"
lockfileVersion: '6.0'

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
    engines: {node: '>=4'}
  /@scope/pkg@1.2.3:
    resolution: {integrity: sha512-def}
"#;
        let packages = parse_pnpm_lock(content).unwrap();
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
    fn parse_pnpm_slash_version_style() {
        let content = r#"
lockfileVersion: 5.4

packages:
  /left-pad/1.3.0:
    resolution:
      integrity: sha1-abc
"#;
        let packages = parse_pnpm_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "left-pad");
        assert_eq!(packages[0].version, "1.3.0");
    }

    #[test]
    fn parse_pnpm_package_key_helpers() {
        assert_eq!(
            parse_pnpm_package_key("/lodash@4.17.21"),
            Some(("lodash", "4.17.21"))
        );
        assert_eq!(
            parse_pnpm_package_key("/@s/p@1.0.0"),
            Some(("@s/p", "1.0.0"))
        );
        assert_eq!(
            parse_pnpm_package_key("/lodash/4.17.21"),
            Some(("lodash", "4.17.21"))
        );
    }
}
