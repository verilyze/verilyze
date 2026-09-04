// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::is_js_lock_file;

/// JavaScript / TypeScript manifest file name (FR-005).
pub const JS_MANIFEST_NAME: &str = "package.json";

/// Discovers `package.json` files under a directory tree.
#[derive(Debug, Default)]
pub struct JsManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl JsManifestFinder {
    /// Create a finder that matches built-in `package.json`.
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
impl ManifestFinder for JsManifestFinder {
    fn language_name(&self) -> &str {
        "javascript"
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        name == JS_MANIFEST_NAME || is_js_lock_file(name)
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
                Some(regexes) => {
                    // FR-006 filters *manifest* names, but JS lockfiles must be
                    // discovered for lock-only roots (no `package.json`).
                    is_js_lock_file(name)
                        || regexes.iter().any(|r| r.is_match(name))
                }
                None => name == JS_MANIFEST_NAME || is_js_lock_file(name),
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
    use std::fs;

    #[test]
    fn language_name_returns_javascript() {
        assert_eq!(JsManifestFinder::new().language_name(), "javascript");
    }

    #[test]
    fn sca_sensitive_basenames_include_manifest_and_locks() {
        let finder = JsManifestFinder::new();
        assert!(finder.is_sca_sensitive_basename("package.json"));
        assert!(finder.is_sca_sensitive_basename("package-lock.json"));
        assert!(
            !finder.is_sca_sensitive_basename("package-lock.json.fixture")
        );
    }

    #[test]
    fn js_manifest_name_constant() {
        assert_eq!(JS_MANIFEST_NAME, "package.json");
    }

    #[test]
    fn with_patterns_invalid_regex_returns_error() {
        assert!(
            JsManifestFinder::with_patterns(vec!["[invalid".to_string()])
                .is_err()
        );
    }

    #[tokio::test]
    async fn find_package_json_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("packages/foo")).unwrap();
        std::fs::write(tmp.join("package.json"), r#"{"name":"root"}"#)
            .unwrap();
        std::fs::write(
            tmp.join("packages/foo/package.json"),
            r#"{"name":"foo"}"#,
        )
        .unwrap();
        std::fs::write(tmp.join("other.txt"), "x").unwrap();

        let finder = JsManifestFinder::new();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want = vec![
            tmp.join("package.json"),
            tmp.join("packages/foo/package.json"),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn find_lockfile_in_lock_only_root() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();

        fs::write(
            tmp.join("package-lock.json"),
            r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/pkg": { "version": "1.0.0" }
  }
}"#,
        )
        .unwrap();

        let finder = JsManifestFinder::new();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();

        assert_eq!(got, vec![tmp.join("package-lock.json")]);
    }
}
