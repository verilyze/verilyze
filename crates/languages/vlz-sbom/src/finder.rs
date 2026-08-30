// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::names::{SBOM_LANGUAGE_NAME, is_sbom_basename};

/// Discovers allowlisted CycloneDX / SPDX JSON SBOM files (FR-038).
#[derive(Debug, Default)]
pub struct SbomManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl SbomManifestFinder {
    /// Create a finder using built-in SBOM basename allowlist.
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
impl ManifestFinder for SbomManifestFinder {
    fn language_name(&self) -> &str {
        SBOM_LANGUAGE_NAME
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        is_sbom_basename(name)
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
        let name = match file_name.to_str() {
            Some(n) => n,
            None => continue,
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let matches = match patterns {
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => is_sbom_basename(name),
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
    use std::io::Write;

    #[test]
    fn language_name_is_sbom() {
        assert_eq!(SbomManifestFinder::new().language_name(), "sbom");
    }

    #[tokio::test]
    async fn find_allowlisted_sboms() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("nested")).unwrap();
        std::fs::File::create(tmp.join("bom.json"))
            .unwrap()
            .write_all(b"{}")
            .unwrap();
        std::fs::File::create(tmp.join("nested").join("app.cdx.json"))
            .unwrap()
            .write_all(b"{}")
            .unwrap();
        std::fs::File::create(tmp.join("inventory.json"))
            .unwrap()
            .write_all(b"{}")
            .unwrap();

        let got = SbomManifestFinder::new().find(tmp).await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|p| p.ends_with("bom.json")));
        assert!(got.iter().any(|p| p.ends_with("app.cdx.json")));
    }
}
