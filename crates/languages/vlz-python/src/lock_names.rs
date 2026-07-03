// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Environment variable for Python lock-file allowlist (Phase 2).
pub const PYTHON_LOCK_FILES_ENV: &str = "VLZ_PYTHON_LOCK_FILES";

/// Python lock file basenames (Appendix A). `pylock.*.toml` handled by [`is_pylock_variant`].
pub const PYTHON_LOCK_FILE_NAMES: &[&str] =
    &["pylock.toml", "poetry.lock", "Pipfile.lock", "uv.lock"];

/// True when `name` is `pylock.toml` or `pylock.*.toml` (PEP 751).
pub fn is_pylock_variant(name: &str) -> bool {
    name == "pylock.toml"
        || (name.starts_with("pylock.") && name.ends_with(".toml"))
}

/// True when `name` is a supported Python lock file basename.
pub fn is_python_lock_file(name: &str) -> bool {
    PYTHON_LOCK_FILE_NAMES.contains(&name) || is_pylock_variant(name)
}

/// True when `path` is a lock-file entry point (orphan or adjacent resolution).
pub fn manifest_is_lock_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_python_lock_file)
}

/// Basename from a `--lock-file` / config entry (path or basename).
pub fn normalize_lock_file_basename(entry: &str) -> String {
    Path::new(entry.trim())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(entry.trim())
        .to_string()
}

/// Normalize and validate a lock-file allowlist; empty input is allowed.
pub fn normalize_lock_file_allowlist(
    entries: &[String],
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for entry in entries {
        let base = normalize_lock_file_basename(entry);
        if base.is_empty() {
            continue;
        }
        if !is_python_lock_file(&base) {
            return Err(format!("unsupported lock file name: {base}"));
        }
        if !out.contains(&base) {
            out.push(base);
        }
    }
    Ok(out)
}

/// True when `allowlist` is empty (scan all supported locks) or `name` is listed.
pub fn lock_name_matches_allowlist(name: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    allowlist
        .iter()
        .any(|entry| normalize_lock_file_basename(entry) == name)
}

/// Keep only lock paths whose basename is in `allowlist` (no-op when empty).
pub fn filter_lock_paths_by_allowlist(
    paths: &[PathBuf],
    allowlist: &[String],
) -> Vec<PathBuf> {
    if allowlist.is_empty() {
        return paths.to_vec();
    }
    paths
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| lock_name_matches_allowlist(n, allowlist))
        })
        .cloned()
        .collect()
}

/// True when `dir` contains at least one supported Python lock file.
pub fn dir_has_any_python_lock(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry.file_name().to_str().is_some_and(is_python_lock_file)
    })
}

/// When `allowlist` is set and `dir` already has lock files, every listed basename must exist.
pub fn verify_lock_allowlist_for_dir(
    dir: &Path,
    allowlist: &[String],
) -> Result<(), String> {
    if allowlist.is_empty() {
        return Ok(());
    }
    if !dir_has_any_python_lock(dir) {
        return Ok(());
    }
    for entry in allowlist {
        let base = normalize_lock_file_basename(entry);
        if !dir.join(&base).is_file() {
            return Err(format!(
                "lock file {base} not found in {}",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// Return orphan lock paths: locks in directories with no Python manifest.
pub fn filter_orphan_locks(
    manifest_paths: &[PathBuf],
    lock_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let dirs_with_manifest: HashSet<&Path> =
        manifest_paths.iter().filter_map(|p| p.parent()).collect();
    lock_paths
        .iter()
        .filter(|lock| {
            lock.parent()
                .is_some_and(|dir| !dirs_with_manifest.contains(dir))
        })
        .cloned()
        .collect()
}

/// Directories containing more than one lock path (for multi-lock warnings).
pub fn dirs_with_multiple_locks(lock_paths: &[PathBuf]) -> HashSet<PathBuf> {
    let mut by_dir: HashMap<PathBuf, usize> = HashMap::new();
    for lock in lock_paths {
        if let Some(dir) = lock.parent() {
            *by_dir.entry(dir.to_path_buf()).or_default() += 1;
        }
    }
    by_dir
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(dir, _)| dir)
        .collect()
}

/// Collect orphan multi-lock directories and lock basenames for stderr warnings.
pub fn orphan_multi_lock_warning_dirs(
    manifest_paths: &[PathBuf],
    lock_paths: &[PathBuf],
) -> Vec<(PathBuf, Vec<String>)> {
    let orphans = filter_orphan_locks(manifest_paths, lock_paths);
    let multi = dirs_with_multiple_locks(&orphans);
    multi
        .into_iter()
        .map(|dir| {
            let names: Vec<String> = orphans
                .iter()
                .filter(|p| p.parent() == Some(dir.as_path()))
                .filter_map(|p| {
                    p.file_name().and_then(|n| n.to_str()).map(str::to_string)
                })
                .collect();
            (dir, names)
        })
        .collect()
}

/// Collect lock paths that are orphans under `root` (for stderr warnings after discovery).
#[allow(dead_code)]
pub fn orphan_lock_dirs_with_multiple_locks(
    manifest_paths: &[PathBuf],
    lock_paths: &[PathBuf],
) -> HashSet<PathBuf> {
    let orphans = filter_orphan_locks(manifest_paths, lock_paths);
    dirs_with_multiple_locks(&orphans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_pylock_variant_matches_pep751_names() {
        assert!(is_pylock_variant("pylock.toml"));
        assert!(is_pylock_variant("pylock.dev.toml"));
        assert!(!is_pylock_variant("pylock.toml.bak"));
        assert!(!is_pylock_variant("poetry.lock"));
    }

    #[test]
    fn is_python_lock_file_includes_appendix_a_names() {
        for name in PYTHON_LOCK_FILE_NAMES {
            assert!(is_python_lock_file(name));
        }
        assert!(is_python_lock_file("pylock.foo.toml"));
        assert!(!is_python_lock_file("requirements.txt"));
    }

    #[test]
    fn manifest_is_lock_file_uses_basename() {
        assert!(manifest_is_lock_file(Path::new("/a/poetry.lock")));
        assert!(!manifest_is_lock_file(Path::new("/a/requirements.txt")));
    }

    #[test]
    fn filter_orphan_locks_skips_when_manifest_in_same_dir() {
        let dir = PathBuf::from("/proj");
        let manifests = vec![dir.join("requirements.txt")];
        let locks = vec![
            dir.join("pylock.toml"),
            dir.join("poetry.lock"),
            PathBuf::from("/other/poetry.lock"),
        ];
        let orphans = filter_orphan_locks(&manifests, &locks);
        assert_eq!(orphans, vec![PathBuf::from("/other/poetry.lock")]);
    }

    #[test]
    fn filter_orphan_locks_returns_all_orphans_in_dir() {
        let dir = PathBuf::from("/locks-only");
        let locks = vec![dir.join("pylock.toml"), dir.join("poetry.lock")];
        let orphans = filter_orphan_locks(&[], &locks);
        assert_eq!(orphans.len(), 2);
    }

    #[test]
    fn dirs_with_multiple_locks_finds_multi_lock_dirs() {
        let locks = vec![
            PathBuf::from("/a/pylock.toml"),
            PathBuf::from("/a/poetry.lock"),
            PathBuf::from("/b/uv.lock"),
        ];
        let dirs = dirs_with_multiple_locks(&locks);
        assert_eq!(dirs.len(), 1);
        assert!(dirs.contains(&PathBuf::from("/a")));
    }

    #[test]
    fn python_manifest_names_excludes_lock_basenames() {
        use crate::finder::PYTHON_MANIFEST_NAMES;
        for name in PYTHON_LOCK_FILE_NAMES {
            assert!(
                !PYTHON_MANIFEST_NAMES.contains(name),
                "{name} should not be a default manifest name"
            );
        }
    }

    #[test]
    fn filter_lock_paths_by_allowlist_keeps_only_listed() {
        let paths = vec![
            PathBuf::from("/a/pylock.toml"),
            PathBuf::from("/a/poetry.lock"),
        ];
        let filtered = filter_lock_paths_by_allowlist(
            &paths,
            &["poetry.lock".to_string()],
        );
        assert_eq!(filtered, vec![PathBuf::from("/a/poetry.lock")]);
    }

    #[test]
    fn verify_lock_allowlist_skips_dir_without_locks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "a==1\n").unwrap();
        verify_lock_allowlist_for_dir(
            dir.path(),
            &["poetry.lock".to_string()],
        )
        .unwrap();
    }

    #[test]
    fn verify_lock_allowlist_errors_when_listed_lock_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("uv.lock"), "version = 1\n").unwrap();
        let err = verify_lock_allowlist_for_dir(
            dir.path(),
            &["poetry.lock".to_string()],
        )
        .unwrap_err();
        assert!(err.contains("poetry.lock"));
    }
}
