// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

/// Supported JavaScript lock file basenames (Appendix A).
pub const JS_LOCK_FILE_NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
];

/// Precedence when multiple locks exist and packageManager is unset.
/// Lower index = higher priority.
const LOCK_PRECEDENCE: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
];

/// True when `name` is a supported JS lock file basename.
pub fn is_js_lock_file(name: &str) -> bool {
    JS_LOCK_FILE_NAMES.contains(&name)
}

/// Map Corepack `packageManager` field value to a preferred lock basename.
pub fn lock_for_package_manager(
    package_manager: &str,
) -> Option<&'static str> {
    let pm = package_manager.split('@').next().unwrap_or(package_manager);
    match pm.trim().to_ascii_lowercase().as_str() {
        "npm" => Some("package-lock.json"),
        "yarn" => Some("yarn.lock"),
        "pnpm" => Some("pnpm-lock.yaml"),
        "bun" => Some("bun.lock"),
        _ => None,
    }
}

/// Choose one lock path from candidates using packageManager hint then
/// fixed precedence. Returns `(chosen, all_present_basenames)`.
pub fn select_lock_file(
    candidates: &[PathBuf],
    package_manager: Option<&str>,
) -> Option<(PathBuf, Vec<String>)> {
    if candidates.is_empty() {
        return None;
    }
    let names: Vec<String> = candidates
        .iter()
        .filter_map(|p| {
            p.file_name().and_then(|n| n.to_str()).map(str::to_string)
        })
        .collect();

    if let Some(pm) = package_manager
        && let Some(want) = lock_for_package_manager(pm)
    {
        if let Some(path) = candidates
            .iter()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(want))
        {
            return Some((path.clone(), names));
        }
        // yarn/pnpm/npm may use alternate names; fall through to precedence.
        if want == "package-lock.json"
            && let Some(path) = candidates.iter().find(|p| {
                p.file_name().and_then(|n| n.to_str())
                    == Some("npm-shrinkwrap.json")
            })
        {
            return Some((path.clone(), names));
        }
    }

    for preferred in LOCK_PRECEDENCE {
        if let Some(path) = candidates.iter().find(|p| {
            p.file_name().and_then(|n| n.to_str()) == Some(*preferred)
        }) {
            return Some((path.clone(), names));
        }
    }
    None
}

/// List lock file paths present in `dir`.
pub fn list_lock_files_in_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for name in JS_LOCK_FILE_NAMES {
        let path = dir.join(name);
        if path.is_file() {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_js_lock_file_matches_appendix_names() {
        for name in JS_LOCK_FILE_NAMES {
            assert!(is_js_lock_file(name));
        }
        assert!(!is_js_lock_file("package.json"));
        assert!(!is_js_lock_file("bun.lockb"));
    }

    #[test]
    fn lock_for_package_manager_parses_corepack() {
        assert_eq!(
            lock_for_package_manager("pnpm@9.0.0"),
            Some("pnpm-lock.yaml")
        );
        assert_eq!(lock_for_package_manager("yarn@1.22.0"), Some("yarn.lock"));
        assert_eq!(
            lock_for_package_manager("npm@10"),
            Some("package-lock.json")
        );
        assert_eq!(lock_for_package_manager("bun@1.2"), Some("bun.lock"));
        assert_eq!(lock_for_package_manager("deno@1"), None);
    }

    #[test]
    fn select_lock_file_uses_precedence() {
        let candidates = vec![
            PathBuf::from("/a/yarn.lock"),
            PathBuf::from("/a/package-lock.json"),
        ];
        let (chosen, names) = select_lock_file(&candidates, None).unwrap();
        assert_eq!(chosen, PathBuf::from("/a/package-lock.json"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn select_lock_file_honors_package_manager() {
        let candidates = vec![
            PathBuf::from("/a/yarn.lock"),
            PathBuf::from("/a/package-lock.json"),
        ];
        let (chosen, _) =
            select_lock_file(&candidates, Some("yarn@4.0.0")).unwrap();
        assert_eq!(chosen, PathBuf::from("/a/yarn.lock"));
    }

    #[test]
    fn select_lock_file_empty_and_npm_shrinkwrap_fallback() {
        assert!(select_lock_file(&[], None).is_none());
        assert!(select_lock_file(&[], Some("npm@10")).is_none());
        let candidates = vec![PathBuf::from("/a/npm-shrinkwrap.json")];
        let (chosen, _) =
            select_lock_file(&candidates, Some("npm@10")).unwrap();
        assert_eq!(chosen, PathBuf::from("/a/npm-shrinkwrap.json"));
        let (chosen, _) =
            select_lock_file(&candidates, Some("unknown-pm")).unwrap();
        assert_eq!(chosen, PathBuf::from("/a/npm-shrinkwrap.json"));
    }

    #[test]
    fn select_lock_file_unknown_basenames_returns_none() {
        let candidates = vec![PathBuf::from("/a/weird.lock")];
        assert!(select_lock_file(&candidates, Some("npm@10")).is_none());
        assert!(select_lock_file(&candidates, None).is_none());
    }

    #[test]
    fn list_lock_files_in_dir_finds_present() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(tmp.join("yarn.lock"), "x").unwrap();
        std::fs::write(tmp.join("package.json"), "{}").unwrap();
        let found = list_lock_files_in_dir(tmp);
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("yarn.lock"));
    }
}
