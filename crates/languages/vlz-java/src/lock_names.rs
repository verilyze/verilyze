// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

/// Supported Java/Gradle lock file basenames (Appendix A).
pub const JAVA_LOCK_FILE_NAMES: &[&str] =
    &["gradle.lockfile", "buildscript-gradle.lockfile"];

const LOCK_PRECEDENCE: &[&str] =
    &["gradle.lockfile", "buildscript-gradle.lockfile"];

/// True when `name` is a supported Gradle lock basename.
pub fn is_java_lock_file(name: &str) -> bool {
    JAVA_LOCK_FILE_NAMES.contains(&name)
}

/// List lock file paths present in `dir`.
pub fn list_lock_files_in_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && is_java_lock_file(name)
        {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Choose lock files from candidates using fixed precedence (all present).
pub fn select_lock_files(candidates: &[PathBuf]) -> Vec<PathBuf> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut chosen = Vec::new();
    for want in LOCK_PRECEDENCE {
        if let Some(path) = candidates
            .iter()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(*want))
        {
            chosen.push(path.clone());
        }
    }
    if chosen.is_empty() {
        chosen.push(candidates[0].clone());
    }
    chosen
}

/// Choose one lock from candidates using fixed precedence. Returns `(chosen, all_basenames)`.
pub fn select_lock_file(
    candidates: &[PathBuf],
) -> Option<(PathBuf, Vec<String>)> {
    let all = select_lock_files(candidates);
    if all.is_empty() {
        return None;
    }
    let names: Vec<String> = candidates
        .iter()
        .filter_map(|p| {
            p.file_name().and_then(|n| n.to_str()).map(str::to_string)
        })
        .collect();
    Some((all[0].clone(), names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_returns_all_lock_files_in_precedence_order() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("gradle.lockfile");
        let b = dir.path().join("buildscript-gradle.lockfile");
        std::fs::write(&a, "").unwrap();
        std::fs::write(&b, "").unwrap();
        let cands = list_lock_files_in_dir(dir.path());
        let chosen = select_lock_files(&cands);
        assert_eq!(chosen.len(), 2);
        assert_eq!(chosen[0].file_name().unwrap(), "gradle.lockfile");
        assert_eq!(
            chosen[1].file_name().unwrap(),
            "buildscript-gradle.lockfile"
        );
    }

    #[test]
    fn select_prefers_gradle_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("gradle.lockfile");
        let b = dir.path().join("buildscript-gradle.lockfile");
        std::fs::write(&a, "").unwrap();
        std::fs::write(&b, "").unwrap();
        let cands = list_lock_files_in_dir(dir.path());
        let (chosen, _) = select_lock_file(&cands).unwrap();
        assert_eq!(chosen.file_name().unwrap(), "gradle.lockfile");
    }
}
