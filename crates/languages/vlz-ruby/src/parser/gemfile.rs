// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;
use vlz_db::{DeclarationKind, Package, RUBYGEMS_ECOSYSTEM};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::util::{is_non_registry_gem_line, strip_line_comment};

fn gem_regex() -> regex::Regex {
    // Quoted names, symbol names (`:rails`), and optional first version constraint.
    regex::Regex::new(
        r#"^\s*gem\s*(?:\(\s*)?(?:['"]([^'"]+)['"]|:([A-Za-z_][A-Za-z0-9_]*))(?:\s*,\s*['"]([^'"]+)['"])?"#,
    )
    .expect("valid Gemfile gem regex")
}

pub fn parse_gemfile(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_gemfile_with_declarations(content, Path::new("Gemfile"))?.0)
}

/// Parse Gemfile-style declarations with FR-036a locations.
pub fn parse_gemfile_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let regex = gem_regex();
    let mut parsed = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let code = strip_line_comment(line);
        if is_non_registry_gem_line(code) {
            continue;
        }
        let Some(captures) = regex.captures(code) else {
            continue;
        };
        let name = captures
            .get(1)
            .or_else(|| captures.get(2))
            .map(|value| value.as_str().to_string())
            .expect("gem regex always captures a name");
        let package = Package {
            name,
            version: captures
                .get(3)
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "*".to_string()),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.to_string()),
        };
        parsed.push(ParsedDependency {
            package,
            path: path.to_path_buf(),
            start_line: (index + 1) as u32,
            end_line: None,
            kind: DeclarationKind::Manifest,
        });
    }
    let packages = parsed.iter().map(|item| item.package.clone()).collect();
    Ok((packages, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_groups_and_skips_non_registry() {
        let input = "group :test do\n gem 'rspec', '~> 3.0'\nend\n\
            gem('rack', '2.2.8')\ngem 'local', path: '../local'\n\
            gem 'remote', git: 'https://example.test/x'\n";
        let (packages, declarations) =
            parse_gemfile_with_declarations(input, Path::new("Gemfile"))
                .unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "rspec");
        assert_eq!(declarations[0].start_line, 2);
    }

    #[test]
    fn skips_hash_rocket_non_registry_and_parses_symbols() {
        let input = "gem :rails, '~> 7.0'\n\
            gem 'local', :path => '../local'\n\
            gem \"remote\", :git => 'https://example.test/x.git'\n\
            gem 'gh', :github => 'org/repo'\n\
            gem \"foo#bar\", \"1.0\" # keep hash in name\n";
        let packages = parse_gemfile(input).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "rails"));
        assert!(
            packages
                .iter()
                .any(|p| p.name == "foo#bar" && p.version == "1.0")
        );
        assert!(!packages.iter().any(|p| p.name == "local"));
        assert!(!packages.iter().any(|p| p.name == "remote"));
        assert!(!packages.iter().any(|p| p.name == "gh"));
    }
}
