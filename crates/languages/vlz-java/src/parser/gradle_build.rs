// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort static extraction from Gradle build scripts (crate-private).

use std::collections::HashMap;
use std::path::Path;

use regex::Regex;
use std::sync::LazyLock;
use vlz_db::{DeclarationKind, MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use crate::coordinate::maven_package_name;
use crate::gradle_root::find_gradle_root;

use super::version_catalog::library_alias_index;

static COORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|compile|testCompile|classpath)\s*\(?\s*[\x27\x22]([^:\x27\x22]+):([^:\x27\x22]+):([^\x27\x22]+)[\x27\x22]",
    )
    .expect("valid gradle coord regex")
});

static CATALOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|compile|testCompile|classpath)\s*\(?\s*libs\.((?:[a-zA-Z][a-zA-Z0-9_]*)(?:\.[a-zA-Z][a-zA-Z0-9_]*)*)(?:\.get\(\))?\s*\)?",
    )
    .expect("valid gradle catalog regex")
});

fn is_skipped_catalog_accessor(accessor: &str) -> bool {
    accessor.starts_with("versions.")
        || accessor.starts_with("bundles.")
        || accessor == "versions"
        || accessor == "bundles"
}

fn load_catalog_index(
    manifest: &Path,
) -> HashMap<String, (String, String, String)> {
    let gradle_root = find_gradle_root(manifest, None);
    let catalog_path = gradle_root.join("gradle").join("libs.versions.toml");
    let content = std::fs::read_to_string(&catalog_path).unwrap_or_default();
    if content.is_empty() {
        return HashMap::new();
    }
    library_alias_index(&content).unwrap_or_default()
}

pub(crate) fn parse_gradle_build_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    let catalog = load_catalog_index(path);
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
        for cap in CATALOG_RE.captures_iter(line) {
            let raw_accessor = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let accessor =
                raw_accessor.strip_suffix(".get").unwrap_or(raw_accessor);
            if accessor.is_empty() || is_skipped_catalog_accessor(accessor) {
                continue;
            }
            let lookup_key = accessor.replace('.', "-");
            let resolved =
                catalog.get(accessor).or_else(|| catalog.get(&lookup_key));
            if let Some((group, artifact, version)) = resolved
                && !group.is_empty()
                && !artifact.is_empty()
                && !version.is_empty()
            {
                out.push(ParsedDependency {
                    package: Package {
                        name: maven_package_name(group, artifact),
                        version: version.clone(),
                        ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
                    },
                    path: path.to_path_buf(),
                    start_line: (line_no + 1) as u32,
                    end_line: None,
                    kind: DeclarationKind::Manifest,
                });
            }
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

    fn isolated_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("vlz-java-gradle-build-")
            .tempdir_in("/tmp")
            .unwrap()
    }

    #[test]
    fn resolves_version_catalog_alias() {
        let dir = isolated_tempdir();
        let root = dir.path();
        std::fs::create_dir_all(root.join("gradle")).unwrap();
        std::fs::write(
            root.join("gradle/libs.versions.toml"),
            r#"
[versions]
guava = "33.0.0-jre"

[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
"#,
        )
        .unwrap();
        let content = r#"
dependencies {
    implementation(libs.guava)
    api libs.guava.get()
}
"#;
        let deps = parse_gradle_build_with_declarations(
            content,
            &root.join("build.gradle"),
        )
        .unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| {
            d.package.name == "com.google.guava:guava"
                && d.package.version == "33.0.0-jre"
        }));
    }

    #[test]
    fn resolves_hyphenated_catalog_alias_with_dots() {
        let dir = isolated_tempdir();
        let root = dir.path();
        std::fs::create_dir_all(root.join("gradle")).unwrap();
        std::fs::write(
            root.join("gradle/libs.versions.toml"),
            "[libraries]\njunit-jupiter = { group = \"org.junit.jupiter\", name = \"junit-jupiter\", version = \"5.10.0\" }\n",
        )
        .unwrap();
        let content =
            "dependencies { testImplementation(libs.junit.jupiter) }\n";
        let deps = parse_gradle_build_with_declarations(
            content,
            &root.join("build.gradle"),
        )
        .unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].package.name, "org.junit.jupiter:junit-jupiter");
        assert_eq!(deps[0].package.version, "5.10.0");
    }

    #[test]
    fn skips_versions_and_bundles_catalog_accessors() {
        let dir = isolated_tempdir();
        let root = dir.path();
        std::fs::create_dir_all(root.join("gradle")).unwrap();
        std::fs::write(
            root.join("gradle/libs.versions.toml"),
            "[versions]\nfoo = \"1.0\"\n[libraries]\nbar = { group = \"g\", name = \"a\", version = \"1.0\" }\n",
        )
        .unwrap();
        let content = r#"
dependencies {
    implementation(libs.versions.foo)
    implementation(libs.bundles.bar)
}
"#;
        let deps = parse_gradle_build_with_declarations(
            content,
            &root.join("build.gradle"),
        )
        .unwrap();
        assert!(deps.is_empty());
    }
}
