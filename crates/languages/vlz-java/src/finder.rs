// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::is_java_lock_file;

/// Default Java/Maven/Gradle manifest basenames (FR-005).
pub const JAVA_MANIFEST_NAMES: &[&str] =
    &["pom.xml", "build.gradle", "build.gradle.kts"];

/// Gradle version catalog basename (also matched under a `gradle/` parent).
pub const JAVA_VERSION_CATALOG_NAME: &str = "libs.versions.toml";

/// Discovers Java manifests and orphan Gradle lock files under a tree.
#[derive(Debug, Default)]
pub struct JavaManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl JavaManifestFinder {
    pub fn new() -> Self {
        Self::default()
    }

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

fn is_default_manifest(path: &Path, name: &str) -> bool {
    if JAVA_MANIFEST_NAMES.contains(&name) {
        return true;
    }
    if name == JAVA_VERSION_CATALOG_NAME {
        return path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("gradle");
    }
    false
}

#[async_trait]
impl ManifestFinder for JavaManifestFinder {
    fn language_name(&self) -> &str {
        "java"
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        JAVA_MANIFEST_NAMES.contains(&name)
            || name == JAVA_VERSION_CATALOG_NAME
            || is_java_lock_file(name)
    }

    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        let mut locks = Vec::new();
        walk_dir_collect(
            root,
            self.patterns.as_deref(),
            &mut manifests,
            &mut locks,
        )?;
        let orphans = filter_orphan_locks(&manifests, &locks);
        manifests.extend(orphans);
        manifests.sort();
        manifests.dedup();
        Ok(manifests)
    }
}

fn walk_dir_collect(
    dir: &Path,
    patterns: Option<&[regex::Regex]>,
    manifests: &mut Vec<PathBuf>,
    locks: &mut Vec<PathBuf>,
) -> Result<(), FinderError> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let manifest_matches = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => is_default_manifest(&path, name),
            };
            if manifest_matches {
                manifests.push(path.clone());
            }
            if is_java_lock_file(name) {
                locks.push(path);
            }
        } else if file_type.is_dir() {
            walk_dir_collect(&path, patterns, manifests, locks)?;
        }
    }
    Ok(())
}

/// Orphan lock files without an adjacent manifest in the same directory.
pub fn filter_orphan_locks(
    manifests: &[PathBuf],
    locks: &[PathBuf],
) -> Vec<PathBuf> {
    let manifest_dirs: HashSet<_> = manifests
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();
    locks
        .iter()
        .filter(|lock| {
            lock.parent()
                .map(|d| !manifest_dirs.contains(d))
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finds_pom_and_gradle_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("pom.xml"), "<project/>").unwrap();
        std::fs::create_dir_all(root.join("gradle")).unwrap();
        std::fs::write(root.join("gradle/libs.versions.toml"), "[versions]\n")
            .unwrap();
        std::fs::write(root.join("build.gradle.kts"), "plugins {}").unwrap();
        let mut found = JavaManifestFinder::new().find(root).await.unwrap();
        found.sort();
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn sca_sensitive_basenames_include_manifests_locks_and_catalog() {
        let finder = JavaManifestFinder::new();
        assert!(finder.is_sca_sensitive_basename("pom.xml"));
        assert!(finder.is_sca_sensitive_basename("gradle.lockfile"));
        assert!(finder.is_sca_sensitive_basename(JAVA_VERSION_CATALOG_NAME));
        assert!(!finder.is_sca_sensitive_basename("pom.xml.fixture"));
    }

    #[tokio::test]
    async fn orphan_lock_discovered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("gradle.lockfile"),
            "a:b:1.0=compile\n",
        )
        .unwrap();
        let found = JavaManifestFinder::new().find(dir.path()).await.unwrap();
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]
    async fn custom_patterns_filter_manifests() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pom.xml"), "<project/>").unwrap();
        std::fs::write(dir.path().join("build.gradle"), "plugins {}").unwrap();
        let finder =
            JavaManifestFinder::with_patterns(vec![r"^pom\.xml$".to_string()])
                .unwrap();
        let found = finder.find(dir.path()).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_name().unwrap(), "pom.xml");
    }

    #[tokio::test]
    async fn walks_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("module");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("pom.xml"), "<project/>").unwrap();
        let found = JavaManifestFinder::new().find(dir.path()).await.unwrap();
        assert_eq!(found.len(), 1);
    }
}
