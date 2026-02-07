// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

#![deny(unsafe_code)]

use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// Python manifest file names (initial set; FR-005). Overridden by regexes when set (FR-006).
const PYTHON_MANIFEST_NAMES: &[&str] = &[
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
];

#[derive(thiserror::Error, Debug)]
pub enum FinderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid regex: {0}")]
    Regex(String),

    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait ManifestFinder: Send + Sync {
    /// Return a list of manifest file paths for the given `root`.
    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError>;
}

/// Default implementation that discovers Python manifest files under a directory tree.
/// When patterns are set (FR-006), file names are matched by regex in order; first match wins.
#[derive(Debug)]
pub struct DefaultManifestFinder {
    /// When Some, use these regexes to match manifest file names; when None, use PYTHON_MANIFEST_NAMES.
    patterns: Option<Vec<regex::Regex>>,
}

impl Default for DefaultManifestFinder {
    fn default() -> Self {
        Self { patterns: None }
    }
}

impl DefaultManifestFinder {
    /// Create a new default manifest finder (uses built-in list).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a finder that matches file names with the given regex patterns (FR-006).
    /// Patterns are evaluated in order; first match wins.
    pub fn with_patterns(patterns: Vec<String>) -> Result<Self, FinderError> {
        let re: Result<Vec<_>, _> = patterns
            .into_iter()
            .map(|s| regex::Regex::new(&s).map_err(|e| FinderError::Regex(e.to_string())))
            .collect();
        Ok(Self {
            patterns: Some(re?),
        })
    }
}

#[async_trait]
impl ManifestFinder for DefaultManifestFinder {
    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        walk_dir(root, self.patterns.as_deref(), &mut manifests)?;
        manifests.sort();
        Ok(manifests)
    }
}

/// Recursively walk from `dir`, appending paths that match known manifest names or regex patterns.
/// Only recurses into real directories (not symlinks) to avoid cycles.
fn walk_dir(
    dir: &Path,
    patterns: Option<&[regex::Regex]>,
    out: &mut Vec<PathBuf>,
) -> Result<(), FinderError> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        let meta = entry.metadata()?;
        if meta.is_file() {
            let matches = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => PYTHON_MANIFEST_NAMES.contains(&name),
            };
            if matches {
                out.push(path);
            }
        } else if meta.is_dir() && !meta.is_symlink() {
            walk_dir(&path, patterns, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[tokio::test]
    async fn find_manifests_in_tree() {
        let tmp = std::env::temp_dir().join("spd_manifest_finder_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("subdir")).unwrap();
        fs::File::create(tmp.join("requirements.txt"))
            .unwrap()
            .write_all(b"foo\n")
            .unwrap();
        fs::File::create(tmp.join("subdir").join("pyproject.toml"))
            .unwrap()
            .write_all(b"[project]\n")
            .unwrap();
        fs::File::create(tmp.join("not-a-manifest.txt")).unwrap();
        fs::File::create(tmp.join("subdir").join("setup.py"))
            .unwrap()
            .write_all(b"from setuptools import setup\n")
            .unwrap();

        let finder = DefaultManifestFinder::new();
        let mut got = finder.find(&tmp).await.unwrap();
        got.sort();
        let mut want = vec![
            tmp.join("requirements.txt"),
            tmp.join("subdir").join("pyproject.toml"),
            tmp.join("subdir").join("setup.py"),
        ];
        want.sort();
        assert_eq!(got, want, "expected {:?}, got {:?}", want, got);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn find_all_five_python_manifest_names_fr005() {
        let tmp = std::env::temp_dir().join("spd_finder_five_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let names = [
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "setup.py",
            "setup.cfg",
        ];
        for n in names {
            fs::File::create(tmp.join(n)).unwrap().write_all(b"\n").unwrap();
        }
        fs::File::create(tmp.join("other.txt")).unwrap();
        let finder = DefaultManifestFinder::new();
        let mut got = finder.find(&tmp).await.unwrap();
        got.sort();
        let mut want: Vec<_> = names.iter().map(|n| tmp.join(n)).collect();
        want.sort();
        assert_eq!(got, want);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn with_patterns_only_requirements_fr006() {
        let tmp = std::env::temp_dir().join("spd_finder_regex_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sub")).unwrap();
        fs::File::create(tmp.join("requirements.txt")).unwrap();
        fs::File::create(tmp.join("sub").join("pyproject.toml")).unwrap();
        let finder = DefaultManifestFinder::with_patterns(vec![
            r"^requirements\.txt$".to_string(),
        ])
        .unwrap();
        let mut got = finder.find(&tmp).await.unwrap();
        got.sort();
        assert_eq!(got, vec![tmp.join("requirements.txt")]);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn with_patterns_invalid_regex_returns_err() {
        let r = DefaultManifestFinder::with_patterns(vec!["[invalid".to_string()]);
        assert!(matches!(r, Err(FinderError::Regex(_))));
    }

    #[tokio::test]
    async fn empty_directory_returns_empty_list() {
        let tmp = std::env::temp_dir().join("spd_finder_empty_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let finder = DefaultManifestFinder::new();
        let got = finder.find(&tmp).await.unwrap();
        assert!(got.is_empty());
        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn symlink_directory_not_traversed() {
        let tmp = std::env::temp_dir().join("spd_finder_symlink_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("realdir")).unwrap();
        fs::File::create(tmp.join("realdir").join("requirements.txt"))
            .unwrap();
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::symlink;
            symlink(tmp.join("realdir"), tmp.join("link")).unwrap();
        }
        let finder = DefaultManifestFinder::new();
        let mut got = finder.find(&tmp).await.unwrap();
        got.sort();
        #[cfg(not(windows))]
        assert_eq!(got.len(), 1);
        #[cfg(not(windows))]
        assert_eq!(got[0], tmp.join("realdir").join("requirements.txt"));
        #[cfg(windows)]
        {
            // Windows: no symlink in test; just ensure one manifest found
            assert_eq!(got.len(), 1);
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn find_nonexistent_path_returns_io_error() {
        let finder = DefaultManifestFinder::new();
        let bad = std::env::temp_dir().join("spd_nonexistent_xyz_12345");
        let r = finder.find(&bad).await;
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), FinderError::Io(_)));
    }
}
