// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use vlz_db::{DeclarationKind, NPM_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

/// Parse yarn.lock (Classic v1 or Berry v2+) into packages.
pub fn parse_yarn_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_yarn_lock_with_declarations(content, Path::new("yarn.lock"))?.0)
}

/// Parse with declaration metadata.
pub fn parse_yarn_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    if is_berry(content) {
        parse_yarn_berry(content, path)
    } else {
        parse_yarn_classic(content, path)
    }
}

fn is_berry(content: &str) -> bool {
    content.contains("__metadata:")
        || content.lines().any(|l| {
            let t = l.trim();
            t.starts_with("__metadata:") || t == "__metadata"
        })
}

fn parse_yarn_classic(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_keys: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;
    let mut block_start: u32 = 1;

    let flush = |keys: &mut Vec<String>,
                 version: &mut Option<String>,
                 start: u32,
                 packages: &mut Vec<Package>,
                 seen: &mut std::collections::HashSet<(String, String)>,
                 parsed: &mut Vec<ParsedDependency>,
                 path: &Path| {
        let Some(ver) = version.take() else {
            keys.clear();
            return;
        };
        for key in keys.drain(..) {
            let name = yarn_name_from_descriptor(&key);
            if name.is_empty() {
                continue;
            }
            let pkg = Package {
                name: name.to_string(),
                version: ver.clone(),
                ecosystem: Some(NPM_ECOSYSTEM.to_string()),
            };
            if seen.insert((pkg.name.clone(), pkg.version.clone())) {
                parsed.push(ParsedDependency {
                    package: pkg.clone(),
                    path: path.to_path_buf(),
                    start_line: start,
                    end_line: None,
                    kind: DeclarationKind::Lockfile,
                });
                packages.push(pkg);
            }
        }
    };

    let mut parsed = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line_no = (i + 1) as u32;
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        // New stanza: unindented key ending with ':'
        if !line.starts_with(' ')
            && !line.starts_with('\t')
            && line.contains(':')
        {
            flush(
                &mut current_keys,
                &mut current_version,
                block_start,
                &mut packages,
                &mut seen,
                &mut parsed,
                path,
            );
            block_start = line_no;
            let header = line.trim().trim_end_matches(':');
            current_keys = split_yarn_classic_keys(header);
            current_version = None;
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("version ") {
            let ver = rest.trim().trim_matches('"');
            current_version = Some(ver.to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version:") {
            // Berry-like field inside classic? treat similarly
            let ver = rest.trim().trim_matches('"');
            current_version = Some(ver.to_string());
        }
    }
    flush(
        &mut current_keys,
        &mut current_version,
        block_start,
        &mut packages,
        &mut seen,
        &mut parsed,
        path,
    );
    Ok((packages, parsed))
}

fn split_yarn_classic_keys(header: &str) -> Vec<String> {
    // "a@^1.0.0", "a@^1.1.0" or a@^1.0.0:
    let mut keys = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in header.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => {
                let k = current.trim().trim_matches('"').to_string();
                if !k.is_empty() {
                    keys.push(k);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let k = current.trim().trim_matches('"').to_string();
    if !k.is_empty() {
        keys.push(k);
    }
    keys
}

fn yarn_name_from_descriptor(descriptor: &str) -> &str {
    // "@scope/pkg@^1.0.0" or "pkg@^1.0.0" or Berry "pkg@npm:^1.0.0"
    let d = descriptor.trim().trim_matches('"');
    if let Some(rest) = d.strip_prefix('@') {
        // scoped: @scope/name@range
        if let Some(slash) = rest.find('/') {
            let after_slash = &rest[slash + 1..];
            if let Some(at) = after_slash.find('@') {
                return &d[..1 + slash + 1 + at];
            }
        }
        return d;
    }
    if let Some(at) = d.find('@') {
        &d[..at]
    } else {
        d
    }
}

fn parse_yarn_berry(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    // Prefer YAML parse; fall back to line-based version: fields if YAML fails
    // on multi-key headers.
    match parse_yarn_berry_yaml(content, path) {
        Ok(v) => Ok(v),
        Err(_) => parse_yarn_berry_lines(content, path),
    }
}

fn parse_yarn_berry_yaml(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let value: serde_norway::Value =
        serde_norway::from_str(content).map_err(|e| {
            ParserError::Parse(format!("yarn berry YAML parse error: {e}"))
        })?;
    let Some(map) = value.as_mapping() else {
        return Err(ParserError::Parse(
            "yarn berry lock is not a mapping".to_string(),
        ));
    };

    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::new();

    for (key, entry) in map {
        let key_str = match key {
            serde_norway::Value::String(s) => s.as_str(),
            _ => continue,
        };
        if key_str == "__metadata" {
            continue;
        }
        let Some(entry_map) = entry.as_mapping() else {
            continue;
        };
        let version = entry_map
            .get(serde_norway::Value::String("version".to_string()))
            .and_then(|v| v.as_str())
            .or_else(|| {
                // version may be unquoted number-like string already
                entry_map.iter().find_map(|(k, v)| {
                    if k.as_str() == Some("version") {
                        v.as_str().or_else(|| v.as_i64().map(|_| ""))
                    } else {
                        None
                    }
                })
            });
        // Prefer resolution field for name when present
        let resolution = entry_map
            .get(serde_norway::Value::String("resolution".to_string()))
            .and_then(|v| v.as_str());

        let Some(ver) = version.filter(|v| !v.is_empty()) else {
            // try stringifying version value
            let ver = entry_map
                .get(serde_norway::Value::String("version".to_string()))
                .map(|v| match v {
                    serde_norway::Value::String(s) => s.clone(),
                    serde_norway::Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .unwrap_or_default();
            if ver.is_empty() {
                continue;
            }
            push_berry_pkg(
                resolution.unwrap_or(key_str),
                &ver,
                path,
                &mut packages,
                &mut seen,
                &mut parsed,
            );
            continue;
        };
        push_berry_pkg(
            resolution.unwrap_or(key_str),
            ver,
            path,
            &mut packages,
            &mut seen,
            &mut parsed,
        );
    }
    Ok((packages, parsed))
}

fn push_berry_pkg(
    descriptor: &str,
    version: &str,
    path: &Path,
    packages: &mut Vec<Package>,
    seen: &mut std::collections::HashSet<(String, String)>,
    parsed: &mut Vec<ParsedDependency>,
) {
    // resolution like "@scope/pkg@npm:1.2.3" or first key of multi-key
    let first = descriptor.split(',').next().unwrap_or(descriptor).trim();
    let name = yarn_name_from_berry_resolution(first);
    if name.is_empty() || name == "__metadata" {
        return;
    }
    if version.starts_with("workspace:") || version.starts_with("patch:") {
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

fn yarn_name_from_berry_resolution(descriptor: &str) -> &str {
    let d = descriptor.trim().trim_matches('"');
    for marker in ["@npm:", "@workspace:", "@patch:", "@file:"] {
        if let Some(idx) = d.find(marker) {
            return &d[..idx];
        }
    }
    yarn_name_from_descriptor(d)
}

fn parse_yarn_berry_lines(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    // Line-based: headers are quoted keys ending with ':', then "  version: x"
    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::new();
    let mut current_header: Option<String> = None;
    let mut block_start = 1u32;

    for (i, line) in content.lines().enumerate() {
        let line_no = (i + 1) as u32;
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("__metadata") {
            current_header = None;
            continue;
        }
        if !line.starts_with(' ') && line.contains(':') {
            current_header = Some(
                line.trim()
                    .trim_end_matches(':')
                    .trim_matches('"')
                    .to_string(),
            );
            block_start = line_no;
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("version:")
            && let Some(header) = current_header.as_deref()
        {
            if header == "__metadata" {
                continue;
            }
            let ver = rest.trim().trim_matches('"');
            if ver.is_empty() || ver.starts_with("workspace:") {
                continue;
            }
            let first = header.split(',').next().unwrap_or(header);
            let name = yarn_name_from_berry_resolution(first);
            if name.is_empty() {
                continue;
            }
            let pkg = Package {
                name: name.to_string(),
                version: ver.to_string(),
                ecosystem: Some(NPM_ECOSYSTEM.to_string()),
            };
            if seen.insert((pkg.name.clone(), pkg.version.clone())) {
                parsed.push(ParsedDependency {
                    package: pkg.clone(),
                    path: path.to_path_buf(),
                    start_line: block_start,
                    end_line: None,
                    kind: DeclarationKind::Lockfile,
                });
                packages.push(pkg);
            }
        }
    }
    Ok((packages, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yarn_classic_basic() {
        let content = r#"# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"#;
        let packages = parse_yarn_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.21");
    }

    #[test]
    fn parse_yarn_classic_scoped() {
        let content = r#"# yarn lockfile v1

"@scope/pkg@^1.0.0":
  version "1.2.3"
"#;
        let packages = parse_yarn_lock(content).unwrap();
        assert_eq!(packages[0].name, "@scope/pkg");
    }

    #[test]
    fn parse_yarn_berry_basic() {
        let content = r#"# yarn berry

__metadata:
  version: 6

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  languageName: node
  linkType: hard
"#;
        let packages = parse_yarn_lock(content).unwrap();
        assert!(
            packages
                .iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21"),
            "got: {packages:?}"
        );
    }

    #[test]
    fn yarn_name_from_descriptor_scoped() {
        assert_eq!(
            yarn_name_from_descriptor("@scope/pkg@^1.0.0"),
            "@scope/pkg"
        );
        assert_eq!(yarn_name_from_descriptor("lodash@^4.0.0"), "lodash");
    }
}
