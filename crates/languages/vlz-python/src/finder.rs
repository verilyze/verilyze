// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

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
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(n) => n,
            None => continue,
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let matches = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => PYTHON_MANIFEST_NAMES.contains(&name),
            };
            if matches {
                out.push(entry.path());
            }
        } else if file_type.is_dir() {
            let path = entry.path();
            walk_dir(&path, patterns, out)?;
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
}
