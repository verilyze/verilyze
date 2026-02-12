// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
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

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use spd_manifest_finder::{FinderError, ManifestFinder};

/// Python manifest file names (initial set; FR-005). Overridden by regexes when set (FR-006).
const PYTHON_MANIFEST_NAMES: &[&str] = &[
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
];

/// Python manifest finder that discovers Python manifest files under a directory tree.
/// When patterns are set (FR-006), file names are matched by regex in order; first match wins.
#[derive(Debug)]
pub struct PythonManifestFinder {
    /// When Some, use these regexes to match manifest file names; when None, use PYTHON_MANIFEST_NAMES.
    patterns: Option<Vec<regex::Regex>>,
}

impl Default for PythonManifestFinder {
    fn default() -> Self {
        Self { patterns: None }
    }
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
            .map(|s| regex::Regex::new(&s).map_err(|e| FinderError::Regex(e.to_string())))
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
        let tmp = std::env::temp_dir().join("spd_python_finder_test");
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

        let finder = PythonManifestFinder::new();
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
    async fn with_patterns_only_requirements_fr006() {
        let tmp = std::env::temp_dir().join("spd_python_finder_regex_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sub")).unwrap();
        fs::File::create(tmp.join("requirements.txt")).unwrap();
        fs::File::create(tmp.join("sub").join("pyproject.toml")).unwrap();
        let finder = PythonManifestFinder::with_patterns(vec![r"^requirements\.txt$".to_string()])
            .unwrap();
        let mut got = finder.find(&tmp).await.unwrap();
        got.sort();
        assert_eq!(got, vec![tmp.join("requirements.txt")]);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn language_name_returns_python() {
        let finder = PythonManifestFinder::new();
        assert_eq!(finder.language_name(), "python");
    }
}
