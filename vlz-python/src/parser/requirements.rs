// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_manifest_parser::ParserError;

/// Parse requirements.txt content into a list of packages (name, version).
/// Skips comments, empty lines, and directive lines (-r, -e, etc.).
/// Version: exact from `==`, first version from `>=`/`<=`/`~=`, else `"any"`.
/// Public for fuzzing (NFR-020).
pub fn parse_requirements_txt(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-r ")
            || line.starts_with("-e ")
            || line.starts_with("--")
            || line.starts_with("-f ")
            || line.starts_with("-i ")
        {
            continue;
        }
        if let Some(pkg) = parse_requirement_line(line) {
            packages.push(pkg);
        }
    }
    Ok(packages)
}

/// Parse a single requirement line into Package (name, version), or None if unparseable.
fn parse_requirement_line(line: &str) -> Option<vlz_db::Package> {
    // Strip inline comment
    let line = line
        .find('#')
        .map(|i| line[..i].trim())
        .unwrap_or(line)
        .trim();
    if line.is_empty() {
        return None;
    }
    // PEP 508: name may have [extras]; strip extras so we get "name" and version spec
    let spec = if let Some(open) = line.find('[') {
        let after_close = line[open..]
            .find(']')
            .map(|c| open + c + 1)
            .unwrap_or(line.len());
        format!("{}{}", line[..open].trim(), line[after_close..].trim())
    } else {
        line.to_string()
    };
    let (name, version) = parse_name_version(&spec)?;
    if name.is_empty() {
        return None;
    }
    Some(vlz_db::Package { name, version })
}

/// Split a requirement spec (no [extras]) into (name, version).
fn parse_name_version(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    // Exact version: name==1.0.0
    if let Some((n, v)) = spec.split_once("==") {
        return Some((n.trim().to_string(), v.trim().to_string()));
    }
    // Version specifiers: take first version-like part
    for sep in ["~=", ">=", "<=", "!=", ">", "<"] {
        if let Some((n, v)) = spec.split_once(sep) {
            let version = v.trim().split(',').next().unwrap_or("").trim().to_string();
            let version = if version.is_empty() {
                "any".to_string()
            } else {
                version
            };
            return Some((n.trim().to_string(), version));
        }
    }
    // No version: name only
    Some((spec.to_string(), "any".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requirement_line_strips_extras() {
        let pkg = parse_requirement_line("foo[dev]==1.0").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_requirement_line_skips_empty_after_comment() {
        assert!(parse_requirement_line("  # x").is_none());
    }

    #[test]
    fn parse_requirement_line_skips_empty_name() {
        assert!(parse_requirement_line("==1.0").is_none());
    }

    #[test]
    fn parse_requirement_line_skips_brackets_only() {
        assert!(parse_requirement_line("[]").is_none());
    }

    #[test]
    fn parse_requirements_txt_skips_double_dash_directive() {
        let content = "foo==1.0\n--extra-index-url https://pypi.org\nbar>=2.0\n";
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[1].name, "bar");
    }
}
