// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::Path;

use vlz_db::{DeclarationKind, MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use crate::coordinate::{maven_package_name, parse_gav_triple};

/// Parse `gradle.lockfile` content into packages.
pub fn parse_gradle_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_gradle_lock_with_declarations(
        content,
        Path::new("gradle.lockfile"),
    )?
    .0)
}

/// Parse lock file with FR-036a declaration metadata.
pub fn parse_gradle_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let mut packages = Vec::new();
    let mut parsed = Vec::new();
    let mut seen = HashSet::new();

    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("empty=") {
            continue;
        }
        let coord = trimmed.split('=').next().unwrap_or(trimmed);
        let Some((group, artifact, version)) = parse_gav_triple(coord) else {
            continue;
        };
        if version.is_empty() {
            continue;
        }
        let name = maven_package_name(&group, &artifact);
        let key = format!("{name}:{version}");
        if !seen.insert(key.clone()) {
            continue;
        }
        let pkg = Package {
            name: name.clone(),
            version: version.clone(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        packages.push(pkg.clone());
        parsed.push(ParsedDependency {
            package: pkg,
            path: path.to_path_buf(),
            start_line: (line_no + 1) as u32,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        });
    }
    Ok((packages, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# Gradle lock
org.springframework:spring-beans:5.0.5.RELEASE=compileClasspath, runtimeClasspath
org.springframework:spring-core:5.0.5.RELEASE=compileClasspath, testCompileClasspath
empty=annotationProcessor
"#;

    #[test]
    fn parses_lock_lines_including_test_classpath() {
        let pkgs = parse_gradle_lock(SAMPLE).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "org.springframework:spring-beans")
        );
    }

    #[test]
    fn dedupes_same_coordinate() {
        let content = "com.a:b:1.0=compile\ncom.a:b:1.0=test\n";
        let pkgs = parse_gradle_lock(content).unwrap();
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn declaration_lines() {
        let (_, parsed) = parse_gradle_lock_with_declarations(
            SAMPLE,
            Path::new("gradle.lockfile"),
        )
        .unwrap();
        assert_eq!(parsed[0].start_line, 2);
        assert_eq!(parsed[0].kind, DeclarationKind::Lockfile);
    }
}
