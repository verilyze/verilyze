// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod composer_json;
mod composer_lock;

use async_trait::async_trait;
use std::path::Path;

use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

pub use composer_json::{
    is_packagist_package_name, parse_composer_json,
    parse_composer_json_with_declarations,
};
pub use composer_lock::{
    parse_composer_lock, parse_composer_lock_with_declarations,
};

/// Maximum accepted size for composer.json manifests.
pub const PHP_MANIFEST_MAX_BYTES: u64 = 1024 * 1024;

/// Maximum accepted size for composer.lock files.
pub const PHP_LOCK_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Parser for PHP Composer `composer.json` / `composer.lock` manifests.
#[derive(Debug, Default)]
pub struct PhpManifestParser;

impl PhpManifestParser {
    /// Create a new Composer manifest parser.
    pub fn new() -> Self {
        Self
    }
}

async fn read_capped(
    path: &Path,
    max_bytes: u64,
) -> Result<String, ParserError> {
    if tokio::fs::metadata(path).await?.len() > max_bytes {
        return Err(ParserError::Parse(format!(
            "PHP Composer file exceeds {max_bytes} byte limit"
        )));
    }
    Ok(tokio::fs::read_to_string(path).await?)
}

#[async_trait]
impl Parser for PhpManifestParser {
    fn language_name(&self) -> &'static str {
        "php"
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let name = manifest
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let content = match name {
            "composer.json" => {
                read_capped(manifest, PHP_MANIFEST_MAX_BYTES).await?
            }
            "composer.lock" => {
                read_capped(manifest, PHP_LOCK_MAX_BYTES).await?
            }
            _ => tokio::fs::read_to_string(manifest).await?,
        };
        let (packages, parsed_dependencies) = match name {
            "composer.json" => {
                parse_composer_json_with_declarations(&content, manifest)?
            }
            "composer.lock" => {
                parse_composer_lock_with_declarations(&content, manifest)?
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

    #[tokio::test]
    async fn rejects_oversized_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("composer.json");
        std::fs::write(&path, vec![b'x'; PHP_MANIFEST_MAX_BYTES as usize + 1])
            .unwrap();
        assert!(PhpManifestParser::new().parse(&path).await.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("composer.lock");
        std::fs::write(&path, vec![b'x'; PHP_LOCK_MAX_BYTES as usize + 1])
            .unwrap();
        assert!(PhpManifestParser::new().parse(&path).await.is_err());
    }

    #[tokio::test]
    async fn parses_composer_json_and_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("composer.json");
        std::fs::write(&manifest, r#"{"require":{"vendor/pkg":"^1.0"}}"#)
            .unwrap();
        let graph = PhpManifestParser::new().parse(&manifest).await.unwrap();
        assert_eq!(graph.packages.len(), 1);

        let other = dir.path().join("notes.txt");
        std::fs::write(&other, "hello\n").unwrap();
        let empty = PhpManifestParser::new().parse(&other).await.unwrap();
        assert!(empty.packages.is_empty());
    }

    #[test]
    fn language_name_is_stable() {
        assert_eq!(PhpManifestParser::new().language_name(), "php");
    }
}
