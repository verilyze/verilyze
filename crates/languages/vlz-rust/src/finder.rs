// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

/// Rust manifest file name (FR-005). Overridden by regexes when set (FR-006).
const RUST_MANIFEST_NAME: &str = "Cargo.toml";

/// Rust manifest finder that discovers Cargo.toml files under a directory tree.
/// When patterns are set (FR-006), file names are matched by regex in order; first match wins.
#[derive(Debug, Default)]
pub struct RustManifestFinder {
    /// When Some, use these regexes to match manifest file names; when None, use RUST_MANIFEST_NAME.
    patterns: Option<Vec<regex::Regex>>,
}

impl RustManifestFinder {
    /// Create a new Rust manifest finder (uses built-in Cargo.toml).
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
impl ManifestFinder for RustManifestFinder {
    fn language_name(&self) -> &str {
        "rust"
    }

    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        walk_dir(root, self.patterns.as_deref(), &mut manifests)?;
        manifests.sort();
        Ok(manifests)
    }
}

/// Recursively walk from `dir`, appending paths that match Cargo.toml or regex patterns.
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
                None => name == RUST_MANIFEST_NAME,
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
    use std::io::Write;

    #[test]
    fn language_name_returns_rust() {
        let finder = RustManifestFinder::new();
        assert_eq!(finder.language_name(), "rust");
    }

    #[test]
    fn with_patterns_creates_finder() {
        let finder = RustManifestFinder::with_patterns(vec![
            "^Cargo\\.toml$".to_string(),
        ])
        .unwrap();
        assert_eq!(finder.language_name(), "rust");
    }

    #[test]
    fn with_patterns_invalid_regex_returns_error() {
        let result =
            RustManifestFinder::with_patterns(vec!["[invalid".to_string()]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn find_cargo_toml_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("crates/foo")).unwrap();
        std::fs::File::create(tmp.join("Cargo.toml"))
            .unwrap()
            .write_all(b"[package]\n")
            .unwrap();
        std::fs::File::create(tmp.join("crates/foo").join("Cargo.toml"))
            .unwrap()
            .write_all(b"[package]\n")
            .unwrap();
        std::fs::File::create(tmp.join("other.txt")).unwrap();

        let finder = RustManifestFinder::new();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want = vec![
            tmp.join("Cargo.toml"),
            tmp.join("crates/foo").join("Cargo.toml"),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn with_patterns_only_root_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::File::create(tmp.join("Cargo.toml")).unwrap();
        std::fs::File::create(tmp.join("sub").join("Cargo.toml")).unwrap();

        let finder = RustManifestFinder::with_patterns(vec![
            "^Cargo\\.toml$".to_string(),
        ])
        .unwrap();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want =
            vec![tmp.join("Cargo.toml"), tmp.join("sub").join("Cargo.toml")];
        want.sort();
        assert_eq!(got, want);

        let finder = RustManifestFinder::with_patterns(vec![
            r"^Cargo\.toml$".to_string(),
        ])
        .unwrap();
        let got = finder.find(tmp).await.unwrap();
        assert!(!got.is_empty());
    }
}
