// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

/// Go manifest file name (FR-005). Overridden by regexes when set (FR-006).
pub const GO_MANIFEST_NAME: &str = "go.mod";

/// Go manifest finder that discovers go.mod files under a directory tree.
/// When patterns are set (FR-006), file names are matched by regex in order;
/// first match wins.
#[derive(Debug, Default)]
pub struct GoManifestFinder {
    /// When Some, use these regexes to match manifest file names; when None,
    /// use GO_MANIFEST_NAME.
    patterns: Option<Vec<regex::Regex>>,
}

impl GoManifestFinder {
    /// Create a new Go manifest finder (uses built-in go.mod).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a finder that matches file names with the given regex patterns
    /// (FR-006). Patterns are evaluated in order; first match wins.
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
impl ManifestFinder for GoManifestFinder {
    fn language_name(&self) -> &str {
        "go"
    }

    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        walk_dir(root, self.patterns.as_deref(), &mut manifests)?;
        manifests.sort();
        Ok(manifests)
    }
}

/// Recursively walk from `dir`, appending paths that match go.mod or regex
/// patterns.
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
                None => name == GO_MANIFEST_NAME,
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
    use std::io::Write;

    #[test]
    fn language_name_returns_go() {
        let finder = GoManifestFinder::new();
        assert_eq!(finder.language_name(), "go");
    }

    #[test]
    fn go_manifest_name_constant() {
        assert_eq!(GO_MANIFEST_NAME, "go.mod");
    }

    #[test]
    fn with_patterns_creates_finder() {
        let finder =
            GoManifestFinder::with_patterns(vec!["^go\\.mod$".to_string()])
                .unwrap();
        assert_eq!(finder.language_name(), "go");
    }

    #[test]
    fn with_patterns_invalid_regex_returns_error() {
        let result =
            GoManifestFinder::with_patterns(vec!["[invalid".to_string()]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn find_go_mod_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("pkg/foo")).unwrap();
        std::fs::File::create(tmp.join("go.mod"))
            .unwrap()
            .write_all(b"module example.com/app\n")
            .unwrap();
        std::fs::File::create(tmp.join("pkg/foo").join("go.mod"))
            .unwrap()
            .write_all(b"module example.com/app/pkg/foo\n")
            .unwrap();
        std::fs::File::create(tmp.join("other.txt")).unwrap();

        let finder = GoManifestFinder::new();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want =
            vec![tmp.join("go.mod"), tmp.join("pkg/foo").join("go.mod")];
        want.sort();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn with_patterns_matches_go_mod() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::File::create(tmp.join("go.mod")).unwrap();
        std::fs::File::create(tmp.join("sub").join("go.mod")).unwrap();

        let finder =
            GoManifestFinder::with_patterns(vec!["^go\\.mod$".to_string()])
                .unwrap();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want =
            vec![tmp.join("go.mod"), tmp.join("sub").join("go.mod")];
        want.sort();
        assert_eq!(got, want);
    }
}
