// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod pubspec_lock;
mod pubspec_yaml;

use async_trait::async_trait;
use std::path::Path;

use vlz_db::{PUBSPEC_LOCK_FILE_NAME, PUBSPEC_MANIFEST_FILE_NAME};
use vlz_manifest_parser::{DependencyGraph, Parser, ParserError, read_capped};

pub use pubspec_lock::{
    is_pub_dev_hosted_url, is_pub_package_name, parse_pubspec_lock,
    parse_pubspec_lock_with_declarations,
};
pub use pubspec_yaml::{
    parse_pubspec_yaml, parse_pubspec_yaml_with_declarations,
};

/// Maximum accepted size for `pubspec.yaml` manifests.
pub const DART_MANIFEST_MAX_BYTES: u64 = 1024 * 1024;

/// Maximum accepted size for `pubspec.lock` files.
pub const DART_LOCK_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Label used in oversized-file errors.
const DART_FILE_LABEL: &str = "Dart pubspec";

/// Parser for Dart / Flutter `pubspec.yaml` / `pubspec.lock` files.
#[derive(Debug, Default)]
pub struct DartManifestParser;

impl DartManifestParser {
    /// Create a new Dart manifest parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for DartManifestParser {
    fn language_name(&self) -> &'static str {
        "dart"
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let name = manifest
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let (packages, parsed_dependencies) = match name {
            PUBSPEC_MANIFEST_FILE_NAME => {
                let content = read_capped(
                    manifest,
                    DART_MANIFEST_MAX_BYTES,
                    DART_FILE_LABEL,
                )
                .await?;
                parse_pubspec_yaml_with_declarations(&content, manifest)?
            }
            PUBSPEC_LOCK_FILE_NAME => {
                let content = read_capped(
                    manifest,
                    DART_LOCK_MAX_BYTES,
                    DART_FILE_LABEL,
                )
                .await?;
                parse_pubspec_lock_with_declarations(&content, manifest)?
            }
            _ => (Vec::new(), Vec::new()),
        };
        Ok(DependencyGraph {
            packages,
            parsed_dependencies,
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_manifest_parser::{Parser, ParserError};

    #[tokio::test]
    async fn rejects_oversized_manifest_and_lock() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(
            &manifest,
            vec![b'x'; DART_MANIFEST_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(DartManifestParser::new().parse(&manifest).await.is_err());
        let lock = dir.path().join("pubspec.lock");
        std::fs::write(&lock, vec![b'x'; DART_LOCK_MAX_BYTES as usize + 1])
            .unwrap();
        assert!(DartManifestParser::new().parse(&lock).await.is_err());
    }

    #[tokio::test]
    async fn parses_manifest_lock_and_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "dependencies:\n  http: ^1.0.0\n").unwrap();
        let graph = DartManifestParser::new().parse(&manifest).await.unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.manifest_path.as_deref(), Some(manifest.as_path()));

        let lock = dir.path().join("pubspec.lock");
        std::fs::write(
            &lock,
            "packages:\n  http:\n    description:\n      name: http\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.2.2\"\n",
        )
        .unwrap();
        let graph = DartManifestParser::new().parse(&lock).await.unwrap();
        assert_eq!(graph.packages[0].version, "1.2.2");

        let other = dir.path().join("notes.txt");
        std::fs::write(&other, "hello\n").unwrap();
        let empty = DartManifestParser::new().parse(&other).await.unwrap();
        assert!(empty.packages.is_empty());
    }

    #[tokio::test]
    async fn malformed_manifest_is_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "dependencies: [unclosed").unwrap();
        let err = DartManifestParser::new()
            .parse(&manifest)
            .await
            .unwrap_err();
        assert!(matches!(err, ParserError::Parse(_)));
    }

    #[test]
    fn language_name_is_stable() {
        assert_eq!(DartManifestParser::new().language_name(), "dart");
    }
}
