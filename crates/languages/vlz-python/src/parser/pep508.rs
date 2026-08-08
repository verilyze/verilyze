// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_db::PYPI_ECOSYSTEM;

/// PEP 508 version comparison operators, longest match first (NFR-024).
pub const VERSION_SPECIFIER_OPERATORS: &[&str] =
    &["===", "==", "~=", "!=", ">=", "<=", ">", "<"];

/// Parse a PEP 508 dependency string into Package (name, version).
pub fn parse_pep508_dependency(spec: &str) -> Option<vlz_db::Package> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let spec = strip_extras_optional(spec)?;
    let spec = strip_marker(&spec);
    let (name, version) = parse_name_version(spec)?;
    if name.is_empty() {
        return None;
    }
    Some(vlz_db::Package {
        name,
        version,
        ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
    })
}

/// Split a requirement spec (no [extras], no marker) into (name, version).
pub fn parse_name_version(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if has_lone_equals(spec) {
        return None;
    }
    if let Some((op_idx, op)) = find_first_operator(spec) {
        let name = spec[..op_idx].trim();
        if !is_valid_package_name(name) {
            return None;
        }
        let version_spec = spec[op_idx + op.len()..].trim();
        let version = parse_version_spec(version_spec)?;
        return Some((name.to_string(), version));
    }
    if !is_valid_package_name(spec) {
        return None;
    }
    Some((spec.to_string(), "any".to_string()))
}

fn strip_extras(spec: &str) -> Option<String> {
    let spec = spec.trim();
    let open = spec.find('[')?;
    let close_rel = spec[open..].find(']')?;
    let after_close = open + close_rel + 1;
    Some(format!(
        "{}{}",
        spec[..open].trim(),
        spec[after_close..].trim()
    ))
}

fn strip_extras_optional(spec: &str) -> Option<String> {
    if spec.contains('[') {
        strip_extras(spec)
    } else {
        Some(spec.to_string())
    }
}

fn strip_marker(spec: &str) -> &str {
    spec.split(';').next().unwrap_or(spec).trim()
}

fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn has_lone_equals(spec: &str) -> bool {
    let bytes = spec.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte != b'=' {
            continue;
        }
        let prev = i.checked_sub(1).map(|j| bytes[j]);
        let next = bytes.get(i + 1).copied();
        let part_of_operator = next == Some(b'=')
            || prev == Some(b'=')
            || matches!(
                prev,
                Some(b'!') | Some(b'>') | Some(b'<') | Some(b'~')
            );
        if !part_of_operator {
            return true;
        }
    }
    false
}

fn find_first_operator(spec: &str) -> Option<(usize, &'static str)> {
    let mut best: Option<(usize, &'static str)> = None;
    for (i, _) in spec.char_indices() {
        for op in VERSION_SPECIFIER_OPERATORS {
            if spec[i..].starts_with(op) {
                if best.is_none_or(|(pos, _)| i < pos) {
                    best = Some((i, op));
                }
                break;
            }
        }
    }
    best
}

fn parse_version_spec(version_spec: &str) -> Option<String> {
    let version_spec = version_spec.trim();
    if version_spec.is_empty() {
        return None;
    }
    let parts: Vec<&str> = version_spec.split(',').map(str::trim).collect();
    if parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    let first_version = parts[0].to_string();
    for part in parts.iter().skip(1) {
        let mut found = false;
        for op in VERSION_SPECIFIER_OPERATORS {
            if let Some(rest) = part.strip_prefix(op) {
                if rest.trim().is_empty() {
                    return None;
                }
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }
    Some(first_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pep508_strips_extras() {
        let pkg = parse_pep508_dependency("foo[dev]==1.0").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_pep508_env_marker() {
        let pkg =
            parse_pep508_dependency("foo>=1.0;python_version>='3'").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_pep508_no_operator() {
        let pkg = parse_pep508_dependency("barepkg").unwrap();
        assert_eq!(pkg.name, "barepkg");
        assert_eq!(pkg.version, "any");
    }

    #[test]
    fn parse_pep508_all_operators() {
        let cases = [
            ("pkg==1.0", "pkg", "1.0"),
            ("pkg===1.0.0", "pkg", "1.0.0"),
            ("pkg~=2.0", "pkg", "2.0"),
            ("pkg!=3.0", "pkg", "3.0"),
            ("pkg>=4.0", "pkg", "4.0"),
            ("pkg<=5.0", "pkg", "5.0"),
            ("pkg>6.0", "pkg", "6.0"),
            ("pkg<7.0", "pkg", "7.0"),
        ];
        for (spec, name, version) in cases {
            let pkg = parse_pep508_dependency(spec).unwrap();
            assert_eq!(pkg.name, name, "spec={spec}");
            assert_eq!(pkg.version, version, "spec={spec}");
        }
    }

    #[test]
    fn parse_pep508_comma_clauses() {
        let pkg = parse_pep508_dependency("foo>=1.0,<2").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_pep508_eq_strips_marker() {
        let pkg =
            parse_pep508_dependency("foo==1.0;python_version>='3'").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_pep508_rejects_lone_equals() {
        assert!(parse_pep508_dependency("foo=1.0").is_none());
        assert!(parse_pep508_dependency("package=version").is_none());
    }

    #[test]
    fn parse_pep508_rejects_empty_name() {
        assert!(parse_pep508_dependency("==1.0").is_none());
    }

    #[test]
    fn parse_pep508_rejects_malformed_extras() {
        assert!(parse_pep508_dependency("foo[dev==1.0").is_none());
    }

    #[test]
    fn parse_pep508_rejects_invalid_trailing_clause() {
        assert!(parse_pep508_dependency("foo>=1.0,notanop").is_none());
    }

    #[test]
    fn parse_pep508_rejects_empty_version_operand() {
        assert!(parse_pep508_dependency("foo>=").is_none());
        assert!(parse_pep508_dependency("foo>=1.0,<").is_none());
    }
}
