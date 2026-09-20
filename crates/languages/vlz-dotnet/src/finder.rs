// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::is_dotnet_lock_file;

/// Built-in .NET project file extensions (FR-005).
pub const DOTNET_PROJECT_EXTENSIONS: &[&str] =
    &[".csproj", ".fsproj", ".vbproj"];

/// True when `name` is a built-in .NET project manifest basename.
pub fn is_dotnet_manifest_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    DOTNET_PROJECT_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// Discovers `*.csproj` / `*.fsproj` / `*.vbproj` under a directory tree.
#[derive(Debug, Default)]
pub struct DotnetManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl DotnetManifestFinder {
    /// Create a finder that matches built-in project extensions.
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
impl ManifestFinder for DotnetManifestFinder {
    fn language_name(&self) -> &str {
        "dotnet"
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        is_dotnet_manifest_name(name) || is_dotnet_lock_file(name)
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
                Some(regexes) => regexes.iter().any(|r| r.is_match(name)),
                None => is_dotnet_manifest_name(name),
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

    #[test]
    fn language_name_returns_dotnet() {
        assert_eq!(DotnetManifestFinder::new().language_name(), "dotnet");
    }

    #[test]
    fn sca_sensitive_basenames_include_manifest_and_lock() {
        let finder = DotnetManifestFinder::new();
        assert!(finder.is_sca_sensitive_basename("App.csproj"));
        assert!(finder.is_sca_sensitive_basename("Lib.fsproj"));
        assert!(finder.is_sca_sensitive_basename("Ui.vbproj"));
        assert!(finder.is_sca_sensitive_basename("packages.lock.json"));
        assert!(!finder.is_sca_sensitive_basename("App.csproj.fixture"));
        assert!(
            !finder.is_sca_sensitive_basename("packages.lock.json.fixture")
        );
    }

    #[test]
    fn is_dotnet_manifest_name_matches_extensions() {
        assert!(is_dotnet_manifest_name("Demo.csproj"));
        assert!(is_dotnet_manifest_name("Demo.FSPROJ"));
        assert!(is_dotnet_manifest_name("Demo.vbproj"));
        assert!(!is_dotnet_manifest_name("packages.lock.json"));
        assert!(!is_dotnet_manifest_name("Demo.csproj.fixture"));
    }

    #[test]
    fn with_patterns_invalid_regex_returns_error() {
        assert!(
            DotnetManifestFinder::with_patterns(vec!["[invalid".to_string()])
                .is_err()
        );
    }

    #[tokio::test]
    async fn find_project_files_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("src/Lib")).unwrap();
        std::fs::write(tmp.join("App.csproj"), "<Project />").unwrap();
        std::fs::write(tmp.join("src/Lib/Lib.fsproj"), "<Project />").unwrap();
        std::fs::write(tmp.join("Ui.vbproj"), "<Project />").unwrap();
        std::fs::write(tmp.join("other.txt"), "x").unwrap();
        // Lock alone is not an orphan entry point in v1.
        std::fs::write(tmp.join("packages.lock.json"), "{}").unwrap();

        let finder = DotnetManifestFinder::new();
        let mut got = finder.find(tmp).await.unwrap();
        got.sort();
        let mut want = vec![
            tmp.join("App.csproj"),
            tmp.join("src/Lib/Lib.fsproj"),
            tmp.join("Ui.vbproj"),
        ];
        want.sort();
        assert_eq!(got, want);
    }
}
