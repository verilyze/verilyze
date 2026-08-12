// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort static extraction from Gradle build scripts (crate-private).

use std::path::Path;

use regex::Regex;
use std::sync::LazyLock;
use vlz_db::{DeclarationKind, MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use crate::coordinate::maven_package_name;

static COORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|compile|testCompile|classpath)\s*\(?\s*[\x27\x22]([^:\x27\x22]+):([^:\x27\x22]+):([^\x27\x22]+)[\x27\x22]",
    )
    .expect("valid gradle coord regex")
});

pub(crate) fn parse_gradle_build_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    let mut out = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        for cap in COORD_RE.captures_iter(line) {
            let group = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let artifact = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let version = cap.get(3).map(|m| m.as_str()).unwrap_or("");
            if group.is_empty() || artifact.is_empty() || version.is_empty() {
                continue;
            }
            out.push(ParsedDependency {
                package: Package {
                    name: maven_package_name(group, artifact),
                    version: version.to_string(),
                    ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
                },
                path: path.to_path_buf(),
                start_line: (line_no + 1) as u32,
                end_line: None,
                kind: DeclarationKind::Manifest,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_implementation_string() {
        let content = r#"
dependencies {
    implementation "com.google.guava:guava:33.0.0-jre"
    testImplementation("org.junit:junit:4.13.2")
}
"#;
        let deps = parse_gradle_build_with_declarations(
            content,
            Path::new("build.gradle"),
        )
        .unwrap();
        assert_eq!(deps.len(), 2);
    }
}
