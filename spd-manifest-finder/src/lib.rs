//! Trait used to discover manifest files inside a project tree.
#![deny(unsafe_code)]

use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// Python manifest file names (initial set; FR-005). Configurable regexes (FR-006) can be added later.
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

    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait ManifestFinder: Send + Sync {
    /// Return a list of manifest file paths for the given `root`.
    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError>;
}

/// Default implementation that discovers Python manifest files under a directory tree.
#[derive(Debug, Default)]
pub struct DefaultManifestFinder;

impl DefaultManifestFinder {
    /// Create a new default manifest finder.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ManifestFinder for DefaultManifestFinder {
    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        walk_dir(root, &mut manifests)?;
        manifests.sort();
        Ok(manifests)
    }
}

/// Recursively walk from `dir`, appending paths that match known manifest names.
/// Only recurses into real directories (not symlinks) to avoid cycles.
fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FinderError> {
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
            if PYTHON_MANIFEST_NAMES.contains(&name) {
                out.push(path);
            }
        } else if meta.is_dir() && !meta.is_symlink() {
            walk_dir(&path, out)?;
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
}
