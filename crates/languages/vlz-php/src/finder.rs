// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::is_php_lock_file;

/// PHP Composer manifest file name (FR-005).
pub const PHP_MANIFEST_NAME: &str = "composer.json";

/// True when `name` is the built-in Composer manifest basename.
pub fn is_php_manifest_name(name: &str) -> bool {
    name == PHP_MANIFEST_NAME
}

/// Discovers `composer.json` files under a directory tree.
#[derive(Debug, Default)]
pub struct PhpManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl PhpManifestFinder {
    /// Create a finder that matches built-in `composer.json`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a finder that matches file names with the given regex patterns
    /// (FR-006).
    pub fn with_patterns(patterns: Vec<String>) -> Result<Self, FinderError> {
        let re: Result<Vec<_>, _> = patterns
            .into_iter()
            .map(|s| {
                regex::Regex::new(&s)
                    .map_err(|e| FinderError::Regex(e.to_string()))
            })
            .collect();
        Ok(Self {
            patterns: Some(re?),
        })
    }
}

#[async_trait]
impl ManifestFinder for PhpManifestFinder {
    fn language_name(&self) -> &str {
        "php"
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        name == PHP_MANIFEST_NAME || is_php_lock_file(name)
    }

    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        walk_dir(root, self.patterns.as_deref(), &mut manifests)?;
        manifests.sort();
        Ok(manifests)
    }
}

fn walk_dir(
    dir: &Path,
    patterns: Option<&[regex::Regex]>,
    out: &mut Vec<PathBuf>,
) -> Result<(), FinderError> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let matches = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => name == PHP_MANIFEST_NAME,
            };
            if matches {
                out.push(entry.path());
            }
        } else if file_type.is_dir() {
            walk_dir(&entry.path(), patterns, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_name_returns_php() {
        assert_eq!(PhpManifestFinder::new().language_name(), "php");
    }

    #[test]
    fn sca_sensitive_basenames_include_manifest_and_lock() {
        let finder = PhpManifestFinder::new();
        assert!(finder.is_sca_sensitive_basename("composer.json"));
        assert!(finder.is_sca_sensitive_basename("composer.lock"));
        assert!(!finder.is_sca_sensitive_basename("composer.json.fixture"));
        assert!(!finder.is_sca_sensitive_basename("composer.lock.fixture"));
    }

    #[test]
    fn php_manifest_name_constant() {
        assert_eq!(PHP_MANIFEST_NAME, "composer.json");
    }

    #[test]
    fn with_patterns_invalid_regex_returns_error() {
        assert!(
            PhpManifestFinder::with_patterns(vec!["[invalid".to_string()])
                .is_err()
        );
    }

    #[tokio::test]
    async fn find_composer_json_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("packages/foo")).unwrap();
        std::fs::write(tmp.join("composer.json"), r#"{"name":"root/app"}"#)
            .unwrap();
        std::fs::write(
            tmp.join("packages/foo/composer.json"),
            r#"{"name":"foo/bar"}"#,
        )
        .unwrap();
        std::fs::write(tmp.join("other.txt"), "x").unwrap();
        // Lock alone is not an orphan entry point in v1.
        std::fs::write(tmp.join("composer.lock"), "{}").unwrap();

        let finder = PhpManifestFinder::new();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want = vec![
            tmp.join("composer.json"),
            tmp.join("packages/foo/composer.json"),
        ];
        want.sort();
        assert_eq!(got, want);
    }
}
