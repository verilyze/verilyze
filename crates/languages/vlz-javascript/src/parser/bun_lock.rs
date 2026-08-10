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
struct BunLockFile {
    #[serde(default)]
    packages: BTreeMap<String, Value>,
}

/// Strip JSONC comments and trailing commas for machine-generated bun.lock.
pub fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' => {
                match chars.peek() {
                    Some('/') => {
                        // line comment
                        chars.next();
                        for nc in chars.by_ref() {
                            if nc == '\n' {
                                out.push('\n');
                                break;
                            }
                        }
                    }
                    Some('*') => {
                        chars.next();
                        let mut prev = '\0';
                        for nc in chars.by_ref() {
                            if prev == '*' && nc == '/' {
                                break;
                            }
                            prev = nc;
                        }
                    }
                    _ => out.push(c),
                }
            }
            ',' => {
                // Peek ahead for trailing comma before } or ]
                let mut lookahead = String::new();
                let mut found_close = false;
                while let Some(&nc) = chars.peek() {
                    if nc.is_whitespace() {
                        lookahead.push(nc);
                        chars.next();
                        continue;
                    }
                    if nc == '}' || nc == ']' {
                        found_close = true;
                    }
                    break;
                }
                if found_close {
                    // skip the comma; keep whitespace
                    out.push_str(&lookahead);
                } else {
                    out.push(',');
                    out.push_str(&lookahead);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parse Bun text lockfile (`bun.lock`, JSONC).
pub fn parse_bun_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_bun_lock_with_declarations(content, Path::new("bun.lock"))?.0)
}

/// Parse with declaration metadata.
pub fn parse_bun_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let cleaned = strip_jsonc(content);
    let lock: BunLockFile = serde_json::from_str(&cleaned).map_err(|e| {
        ParserError::Parse(format!("bun.lock parse error: {e}"))
    })?;

    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::new();

    for (key, entry) in &lock.packages {
        // Keys like "lodash" or "@scope/pkg"; values are often arrays:
        // ["lodash@version", {...}, "hash"]
        let (name, version) = match entry {
            Value::Array(arr) => {
                let first = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                parse_bun_pkg_ref(first).unwrap_or_else(|| {
                    (key.as_str(), extract_version_from_key(key))
                })
            }
            Value::Object(map) => {
                let ver =
                    map.get("version").and_then(|v| v.as_str()).unwrap_or("");
                (key.as_str(), ver)
            }
            Value::String(s) => {
                parse_bun_pkg_ref(s).unwrap_or((key.as_str(), s.as_str()))
            }
            _ => continue,
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        if version.starts_with("workspace:") || version.starts_with("file:") {
            continue;
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
    Ok((packages, parsed))
}

fn parse_bun_pkg_ref(s: &str) -> Option<(&str, &str)> {
    // "lodash@4.17.21" or "@scope/pkg@1.0.0"
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('@') {
        let slash = rest.find('/')?;
        let after = &rest[slash + 1..];
        let at = after.find('@')?;
        let name_end = 1 + slash + 1 + at;
        Some((&s[..name_end], &s[name_end + 1..]))
    } else {
        let at = s.find('@')?;
        Some((&s[..at], &s[at + 1..]))
    }
}

fn extract_version_from_key(_key: &str) -> &str {
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jsonc_removes_comments_and_trailing_commas() {
        let input = r#"{
  // comment
  "a": 1,
  /* block */
  "b": 2,
}"#;
        let cleaned = strip_jsonc(input);
        let v: Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], 2);
    }

    #[test]
    fn parse_bun_lock_packages_array() {
        let content = r#"{
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21", {}, "hash"],
    "@scope/pkg": ["@scope/pkg@1.2.3", {}, "hash2"],
  }
}"#;
        let packages = parse_bun_lock(content).unwrap();
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
    fn strip_jsonc_handles_escapes_and_slash() {
        let input = r#"{ "a": "say \"hi\"", "path": "a/b" }"#;
        let cleaned = strip_jsonc(input);
        let v: Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(v["a"], "say \"hi\"");
        assert_eq!(v["path"], "a/b");
    }

    #[test]
    fn parse_bun_lock_object_string_and_skips() {
        let content = r#"{
  "packages": {
    "obj": { "version": "1.2.3" },
    "str": "str@2.0.0",
    "bad": 123,
    "empty": ["", {}],
    "ws": ["ws@workspace:.", {}],
    "file": { "version": "file:../x" },
    "fallback": ["not-a-ref", {}]
  }
}"#;
        let packages = parse_bun_lock(content).unwrap();
        assert!(
            packages
                .iter()
                .any(|p| p.name == "obj" && p.version == "1.2.3")
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "str" && p.version == "2.0.0")
        );
        assert!(!packages.iter().any(|p| p.name == "ws"));
        assert!(!packages.iter().any(|p| p.name == "file"));
        assert!(!packages.iter().any(|p| p.name == "fallback"));
        assert!(!packages.iter().any(|p| p.name == "bad"));
    }

    #[test]
    fn parse_bun_lock_invalid_json_errors() {
        let err = parse_bun_lock("{").unwrap_err();
        assert!(err.to_string().contains("bun.lock"));
    }
}
