// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod gradle_build;
mod gradle_lock;
mod pom_xml;
mod version_catalog;

use async_trait::async_trait;
use std::path::Path;

use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

pub use gradle_lock::{
    parse_gradle_lock, parse_gradle_lock_with_declarations,
};
pub use pom_xml::{parse_pom_xml, parse_pom_xml_with_declarations};
pub use version_catalog::{
    parse_version_catalog, parse_version_catalog_with_declarations,
};

/// Parser for Java/Kotlin Maven and Gradle manifests.
#[derive(Debug, Default)]
pub struct JavaManifestParser;

impl JavaManifestParser {
    pub fn new() -> Self {
        Self
    }
}

fn is_version_catalog(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some("libs.versions.toml")
}

fn is_gradle_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(crate::lock_names::is_java_lock_file)
}

fn is_pom(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some("pom.xml")
}

fn is_gradle_build(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "build.gradle" || n == "build.gradle.kts")
}

#[async_trait]
impl Parser for JavaManifestParser {
    fn language_name(&self) -> &'static str {
        "java"
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let content = tokio::fs::read_to_string(manifest).await?;
        let parsed = if is_gradle_lock(manifest) {
            parse_gradle_lock_with_declarations(&content, manifest)?.1
        } else if is_version_catalog(manifest) {
            parse_version_catalog_with_declarations(&content, manifest)?
        } else if is_pom(manifest) {
            parse_pom_xml_with_declarations(&content, manifest)?
        } else if is_gradle_build(manifest) {
            gradle_build::parse_gradle_build_with_declarations(
                &content, manifest,
            )?
        } else {
            return Err(ParserError::Parse(format!(
                "unsupported Java manifest: {}",
                manifest.display()
            )));
        };
        let packages: Vec<_> = parsed
            .iter()
            .filter(|d| !d.package.version.is_empty())
            .map(|d| d.package.clone())
            .collect();
        Ok(DependencyGraph {
            packages,
            parsed_dependencies: parsed,
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_name_is_java() {
        assert_eq!(JavaManifestParser::new().language_name(), "java");
    }

    #[tokio::test]
    async fn parse_each_manifest_kind() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("pom.xml"),
            r#"<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>"#,
        )
        .unwrap();
        std::fs::write(
            root.join("build.gradle"),
            r#"dependencies { implementation "com.example:lib:1.0" }"#,
        )
        .unwrap();
        std::fs::create_dir_all(root.join("gradle")).unwrap();
        std::fs::write(
            root.join("gradle/libs.versions.toml"),
            "[libraries]\nlib = { group = \"g\", name = \"a\", version = \"1.0\" }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.lock:pkg:1.0=compileClasspath\n",
        )
        .unwrap();
        let parser = JavaManifestParser::new();
        assert!(
            !parser
                .parse(&root.join("pom.xml"))
                .await
                .unwrap()
                .packages
                .is_empty()
        );
        assert!(
            !parser
                .parse(&root.join("build.gradle"))
                .await
                .unwrap()
                .packages
                .is_empty()
        );
        assert!(
            !parser
                .parse(&root.join("gradle/libs.versions.toml"))
                .await
                .unwrap()
                .packages
                .is_empty()
        );
        assert!(
            !parser
                .parse(&root.join("gradle.lockfile"))
                .await
                .unwrap()
                .packages
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unsupported_manifest_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("random.txt");
        std::fs::write(&path, "nope").unwrap();
        let err = JavaManifestParser::new().parse(&path).await.unwrap_err();
        assert!(err.to_string().contains("unsupported Java manifest"));
    }
}
