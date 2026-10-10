// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use vlz_db::PUBSPEC_LOCK_FILE_NAME;

/// Supported Dart / Flutter lock file basenames (Appendix A).
pub const DART_LOCK_FILE_NAMES: &[&str] = &[PUBSPEC_LOCK_FILE_NAME];

/// True when `name` is a supported Dart lock file basename.
pub fn is_dart_lock_file(name: &str) -> bool {
    DART_LOCK_FILE_NAMES.contains(&name)
}

/// Promote lock paths whose directory has no `pubspec.yaml` entry point.
///
/// Locks beside a manifest stay non-orphan and resolve via the manifest.
pub fn filter_orphan_locks(
    manifests: &[PathBuf],
    locks: &[PathBuf],
) -> Vec<PathBuf> {
    let manifest_dirs: HashSet<&Path> =
        manifests.iter().filter_map(|p| p.parent()).collect();
    locks
        .iter()
        .filter(|lock| {
            lock.parent()
                .is_some_and(|dir| !manifest_dirs.contains(dir))
        })
        .cloned()
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn is_dart_lock_file_matches_pubspec_lock_only() {
        assert!(is_dart_lock_file("pubspec.lock"));
        assert!(!is_dart_lock_file("pubspec.yaml"));
        assert!(!is_dart_lock_file("pubspec.lock.fixture"));
        assert_eq!(DART_LOCK_FILE_NAMES, &["pubspec.lock"]);
    }

    #[test]
    fn orphan_filter_skips_locks_beside_a_manifest() {
        let manifests = vec![PathBuf::from("/app/pubspec.yaml")];
        let locks = vec![
            PathBuf::from("/app/pubspec.lock"),
            PathBuf::from("/vendor/pubspec.lock"),
        ];
        assert_eq!(
            filter_orphan_locks(&manifests, &locks),
            vec![PathBuf::from("/vendor/pubspec.lock")]
        );
    }

    #[test]
    fn orphan_filter_keeps_all_locks_without_manifests() {
        let locks = vec![PathBuf::from("/a/pubspec.lock")];
        assert_eq!(filter_orphan_locks(&[], &locks), locks);
    }
}
