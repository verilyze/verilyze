// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

const SETTINGS_NAMES: &[&str] = &["settings.gradle", "settings.gradle.kts"];

/// True when `name` is a Gradle settings file (internal root detection only).
#[allow(dead_code)]
pub fn is_settings_gradle(name: &str) -> bool {
    SETTINGS_NAMES.contains(&name)
}

fn is_gradle_build_path(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        n == "build.gradle"
            || n == "build.gradle.kts"
            || n.ends_with(".gradle")
            || n.ends_with(".gradle.kts")
    })
}

fn gradle_start_dir(start: &Path) -> PathBuf {
    if start.is_file() || is_gradle_build_path(start) {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    }
}

/// Find the Gradle multi-module root containing `settings.gradle*` at or above `start`.
/// Stops at `scan_root` when provided.
pub fn find_gradle_root(start: &Path, scan_root: Option<&Path>) -> PathBuf {
    let mut dir = gradle_start_dir(start);
    loop {
        if SETTINGS_NAMES.iter().any(|n| dir.join(n).is_file()) {
            return dir;
        }
        if scan_root.is_some_and(|root| dir == root) {
            return dir;
        }
        if !dir.pop() {
            break;
        }
        if scan_root.is_some_and(|root| !dir.starts_with(root)) {
            break;
        }
    }
    gradle_start_dir(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_root_with_settings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("settings.gradle"), "rootProject.name = 'x'")
            .unwrap();
        let sub = root.join("app");
        std::fs::create_dir_all(&sub).unwrap();
        assert_eq!(
            find_gradle_root(&sub.join("build.gradle"), Some(root)),
            root.to_path_buf()
        );
    }

    #[test]
    fn falls_back_to_module_without_settings() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("app");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("build.gradle"), "plugins {}").unwrap();
        assert_eq!(find_gradle_root(&sub.join("build.gradle"), None), sub);
    }

    #[test]
    fn treats_missing_build_gradle_as_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let build = root.join("build.gradle");
        assert_eq!(find_gradle_root(&build, None), root.to_path_buf());
    }

    #[test]
    fn is_settings_gradle_name() {
        assert!(is_settings_gradle("settings.gradle"));
        assert!(is_settings_gradle("settings.gradle.kts"));
        assert!(!is_settings_gradle("build.gradle"));
    }
}
