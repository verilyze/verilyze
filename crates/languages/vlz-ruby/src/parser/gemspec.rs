// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;
use vlz_db::{DeclarationKind, Package, RUBYGEMS_ECOSYSTEM};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::util::{is_non_registry_gem_line, strip_line_comment};

fn dependency_regex() -> regex::Regex {
    regex::Regex::new(
        r#"\.(?:add_dependency|add_runtime_dependency|add_development_dependency)\s*(?:\(\s*)?(?:['"]([^'"]+)['"]|:([A-Za-z_][A-Za-z0-9_]*))(?:\s*,\s*['"]([^'"]+)['"])?"#,
    )
    .expect("valid gemspec dependency regex")
}

pub fn parse_gemspec(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(
        parse_gemspec_with_declarations(
            content,
            Path::new("package.gemspec"),
        )?
        .0,
    )
}

/// Parse runtime and development gemspec dependencies with locations.
pub fn parse_gemspec_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let regex = dependency_regex();
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
            .expect("gemspec regex always captures a name");
        parsed.push(ParsedDependency {
            package: Package {
                name,
                version: captures
                    .get(3)
                    .map(|value| value.as_str().to_string())
                    .unwrap_or_else(|| "*".to_string()),
                ecosystem: Some(RUBYGEMS_ECOSYSTEM.to_string()),
            },
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
    fn includes_runtime_and_development_dependencies() {
        let input = "s.add_dependency 'rack', '2.2.8'\n\
            s.add_development_dependency(\"rspec\", \"3.12.0\")\n";
        let packages = parse_gemspec(input).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|item| item.name == "rspec"));
    }

    #[test]
    fn skips_hash_rocket_sources_and_parses_symbol_names() {
        let input = "s.add_dependency :rack, '2.2.8'\n\
            s.add_dependency 'local', :path => '../local'\n\
            s.add_runtime_dependency \"foo#bar\", \"1.0\" # note\n";
        let packages = parse_gemspec(input).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "rack"));
        assert!(packages.iter().any(|p| p.name == "foo#bar"));
        assert!(!packages.iter().any(|p| p.name == "local"));
    }
}
