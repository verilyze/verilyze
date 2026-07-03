// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::{filter_orphan_locks, is_python_lock_file};

/// Python manifest file names (FR-005). Overridden by regexes when set (FR-006).
/// `setup.py` is parsed via AST (see `parser/setup_py.rs`); dynamic/runtime deps
/// are not extracted.
pub const PYTHON_MANIFEST_NAMES: &[&str] = &[
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.cfg",
    "setup.py",
];

/// Python manifest finder that discovers Python manifest files under a directory tree.
/// When patterns are set (FR-006), file names are matched by regex in order; first match wins.
#[derive(Debug, Default)]
pub struct PythonManifestFinder {
    /// When Some, use these regexes to match manifest file names; when None, use PYTHON_MANIFEST_NAMES.
    patterns: Option<Vec<regex::Regex>>,
}

impl PythonManifestFinder {
    /// Create a new Python manifest finder (uses built-in list).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a finder that matches file names with the given regex patterns (FR-006).
    /// Patterns are evaluated in order; first match wins.
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
impl ManifestFinder for PythonManifestFinder {
    fn language_name(&self) -> &str {
        "python"
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

/// Recursively walk from `dir`, collecting manifest paths and lock file paths.
fn walk_dir_collect(
    dir: &Path,
    patterns: Option<&[regex::Regex]>,
    manifests: &mut Vec<PathBuf>,
    locks: &mut Vec<PathBuf>,
) -> Result<(), FinderError> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(n) => n,
            None => continue,
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let manifest_matches = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => PYTHON_MANIFEST_NAMES.contains(&name),
            };
            if manifest_matches {
                manifests.push(entry.path());
            }
            if is_python_lock_file(name) {
                locks.push(entry.path());
            }
        } else if file_type.is_dir() {
            walk_dir_collect(&entry.path(), patterns, manifests, locks)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_name_returns_python() {
        let finder = PythonManifestFinder::new();
        assert_eq!(finder.language_name(), "python");
    }

    #[test]
    fn setup_py_in_default_manifest_names() {
        assert!(PYTHON_MANIFEST_NAMES.contains(&"setup.py"));
    }

    #[test]
    fn setup_cfg_in_default_manifest_names() {
        assert!(PYTHON_MANIFEST_NAMES.contains(&"setup.cfg"));
    }

    #[test]
    fn requirements_txt_in_default_manifest_names() {
        assert!(PYTHON_MANIFEST_NAMES.contains(&"requirements.txt"));
    }

    #[test]
    fn orphan_pylock_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let pylock = dir.path().join("pylock.toml");
        std::fs::write(
            &pylock,
            "[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let finder = PythonManifestFinder::new();
        let found = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(finder.find(dir.path()))
            .unwrap();
        assert_eq!(found, vec![pylock]);
    }

    #[test]
    fn multiple_orphan_locks_all_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let pylock = dir.path().join("pylock.toml");
        let poetry = dir.path().join("poetry.lock");
        std::fs::write(
            &pylock,
            "[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            &poetry,
            "[[package]]\nname = \"b\"\nversion = \"2.0\"\n",
        )
        .unwrap();
        let finder = PythonManifestFinder::new();
        let found = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(finder.find(dir.path()))
            .unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.contains(&pylock));
        assert!(found.contains(&poetry));
    }

    #[test]
    fn colocated_manifest_and_lock_discovers_manifest_only() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        let pylock = dir.path().join("pylock.toml");
        std::fs::write(&req, "a==1.0\n").unwrap();
        std::fs::write(
            &pylock,
            "[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let finder = PythonManifestFinder::new();
        let found = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(finder.find(dir.path()))
            .unwrap();
        assert_eq!(found, vec![req]);
    }
}
