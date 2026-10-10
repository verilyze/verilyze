// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_db::PUBSPEC_MANIFEST_FILE_NAME;
use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::{filter_orphan_locks, is_dart_lock_file};

/// True when `name` is the built-in Dart manifest basename.
pub fn is_dart_manifest_name(name: &str) -> bool {
    name == PUBSPEC_MANIFEST_FILE_NAME
}

/// Discovers `pubspec.yaml` files (and orphan `pubspec.lock` files) under a
/// directory tree.
#[derive(Debug, Default)]
pub struct DartManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl DartManifestFinder {
    /// Create a finder that matches built-in `pubspec.yaml`.
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
impl ManifestFinder for DartManifestFinder {
    fn language_name(&self) -> &str {
        "dart"
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        is_dart_manifest_name(name) || is_dart_lock_file(name)
    }

    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        let mut locks = Vec::new();
        walk_dir(root, self.patterns.as_deref(), &mut manifests, &mut locks)?;
        let orphans = filter_orphan_locks(&manifests, &locks);
        manifests.extend(orphans);
        manifests.sort();
        manifests.dedup();
        Ok(manifests)
    }
}

fn walk_dir(
    dir: &Path,
    patterns: Option<&[regex::Regex]>,
    manifests: &mut Vec<PathBuf>,
    locks: &mut Vec<PathBuf>,
) -> Result<(), FinderError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let matches_manifest = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => is_dart_manifest_name(name),
            };
            if matches_manifest {
                manifests.push(entry.path());
            }
            if is_dart_lock_file(name) {
                locks.push(entry.path());
            }
        } else if file_type.is_dir() {
            walk_dir(&entry.path(), patterns, manifests, locks)?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_name_is_dart() {
        assert_eq!(DartManifestFinder::new().language_name(), "dart");
    }

    #[test]
    fn sca_sensitive_basenames_include_manifest_and_lock() {
        let finder = DartManifestFinder::new();
        assert!(finder.is_sca_sensitive_basename("pubspec.yaml"));
        assert!(finder.is_sca_sensitive_basename("pubspec.lock"));
        assert!(!finder.is_sca_sensitive_basename("pubspec.yaml.fixture"));
        assert!(!finder.is_sca_sensitive_basename("pubspec.lock.fixture"));
    }

    #[test]
    fn manifest_name_helper() {
        assert!(is_dart_manifest_name("pubspec.yaml"));
        assert!(!is_dart_manifest_name("pubspec.yml"));
    }

    #[test]
    fn with_patterns_invalid_regex_returns_error() {
        assert!(
            DartManifestFinder::with_patterns(vec!["[invalid".to_string()])
                .is_err()
        );
    }

    #[tokio::test]
    async fn find_pubspec_in_tree_and_orphan_lock() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("packages/foo")).unwrap();
        std::fs::create_dir_all(tmp.join("vendor")).unwrap();
        std::fs::write(tmp.join("pubspec.yaml"), "name: app\n").unwrap();
        std::fs::write(tmp.join("pubspec.lock"), "packages: {}\n").unwrap();
        std::fs::write(tmp.join("packages/foo/pubspec.yaml"), "name: foo\n")
            .unwrap();
        std::fs::write(tmp.join("vendor/pubspec.lock"), "packages: {}\n")
            .unwrap();
        std::fs::write(tmp.join("other.txt"), "x").unwrap();

        let mut got = DartManifestFinder::new().find(tmp).await.unwrap();
        got.sort();
        let mut want = vec![
            tmp.join("pubspec.yaml"),
            tmp.join("packages/foo/pubspec.yaml"),
            tmp.join("vendor/pubspec.lock"),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn custom_patterns_replace_builtin_manifest_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pubspec.yaml"), "name: a\n").unwrap();
        std::fs::write(dir.path().join("custom.yaml"), "name: b\n").unwrap();
        let finder =
            DartManifestFinder::with_patterns(vec!["^custom\\.yaml$".into()])
                .unwrap();
        let got = finder.find(dir.path()).await.unwrap();
        assert_eq!(got, vec![dir.path().join("custom.yaml")]);
    }
}
