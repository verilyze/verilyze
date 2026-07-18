// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::pep508::parse_pep508_dependency;
use std::path::Path;
use vlz_db::DeclarationKind;
use vlz_manifest_parser::{ParsedDependency, ParserError};

/// Parse requirements.txt with declaration line metadata.
pub fn parse_requirements_txt_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    let mut parsed = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let start_line = (i + 1) as u32;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("-r ")
            || trimmed.starts_with("-e ")
            || trimmed.starts_with("--")
            || trimmed.starts_with("-f ")
            || trimmed.starts_with("-i ")
        {
            continue;
        }
        if let Some(pkg) = parse_requirement_line(trimmed) {
            parsed.push(ParsedDependency {
                package: pkg,
                path: path.to_path_buf(),
                start_line,
                end_line: None,
                kind: DeclarationKind::Manifest,
            });
        }
    }
    Ok(parsed)
}

/// Parse requirements.txt content into a list of packages (name, version).
/// Skips comments, empty lines, and directive lines (-r, -e, etc.).
/// Version: exact from `==`, first version from `>=`/`<=`/`~=`, else `"any"`.
/// Public for fuzzing (NFR-020).
pub fn parse_requirements_txt(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ParserError> {
    Ok(parse_requirements_txt_with_declarations(
        content,
        Path::new("requirements.txt"),
    )?
    .into_iter()
    .map(|dep| dep.package)
    .collect())
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
    fn parse_requirements_txt_with_declarations_records_lines() {
        let content = "# comment\nfoo==1.0\n\nbar>=2.0\n";
        let deps = parse_requirements_txt_with_declarations(
            content,
            std::path::Path::new("requirements.txt"),
        )
        .unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].start_line, 2);
        assert_eq!(deps[1].start_line, 4);
    }

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
