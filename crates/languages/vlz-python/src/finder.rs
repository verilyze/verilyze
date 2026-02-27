// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

/// Python manifest file names (FR-005). Overridden by regexes when set (FR-006).
/// setup.py is intentionally excluded -- parsing is deferred (see Appendix A in PRD).
/// Discovering setup.py without a parser would cause silent false negatives (the tool
/// would report "no vulnerabilities found" without actually checking any dependencies).
const PYTHON_MANIFEST_NAMES: &[&str] =
    &["requirements.txt", "pyproject.toml", "Pipfile", "setup.cfg"];

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

    #[test]
    fn language_name_returns_python() {
        let finder = PythonManifestFinder::new();
        assert_eq!(finder.language_name(), "python");
    }

    #[test]
    fn setup_py_not_in_default_manifest_names() {
        // FR-005 / Appendix A: setup.py parsing is deferred; the finder must not
        // discover it by default to avoid silent false negatives (no CVE check performed
        // but tool reports "no vulnerabilities found").
        assert!(
            !PYTHON_MANIFEST_NAMES.contains(&"setup.py"),
            "setup.py must not be in the default manifest list until parsing is implemented"
        );
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
