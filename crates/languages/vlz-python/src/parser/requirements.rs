// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::pep508::parse_pep508_dependency;
use vlz_manifest_parser::ParserError;

/// Parse requirements.txt content into a list of packages (name, version).
/// Skips comments, empty lines, and directive lines (-r, -e, etc.).
/// Version: exact from `==`, first version from `>=`/`<=`/`~=`, else `"any"`.
/// Public for fuzzing (NFR-020).
pub fn parse_requirements_txt(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ParserError> {
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
    let line = line
        .find('#')
        .map(|i| line[..i].trim())
        .unwrap_or(line)
        .trim();
    if line.is_empty() || line == "[]" {
        return None;
    }
    parse_pep508_dependency(line)
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
        let content =
            "foo==1.0\n--extra-index-url https://pypi.org\nbar>=2.0\n";
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[1].name, "bar");
    }
}
