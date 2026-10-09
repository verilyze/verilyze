// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Supported NuGet lock file basenames (Appendix A).
pub const DOTNET_LOCK_FILE_NAMES: &[&str] = &["packages.lock.json"];

/// True when `name` is a committed NuGet `packages.lock.json` basename.
pub fn is_packages_lock_json(name: &str) -> bool {
    name.eq_ignore_ascii_case("packages.lock.json")
}

/// True when `name` is a supported .NET / NuGet lock file basename.
pub fn is_dotnet_lock_file(name: &str) -> bool {
    is_packages_lock_json(name)
        || name.eq_ignore_ascii_case("project.assets.json")
        || name.ends_with(".deps.json")
}

/// Promote lock paths whose directory has no .NET project / packages.config.
///
/// Used for orphan `packages.lock.json` entry points (HC-10). Same-directory
/// locks next to a project stay non-orphan and resolve via the project ladder.
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

    #[test]
    fn is_dotnet_lock_file_matches_packages_lock_json() {
        assert!(is_dotnet_lock_file("packages.lock.json"));
        assert!(is_dotnet_lock_file("Packages.Lock.JSON"));
        assert!(is_packages_lock_json("packages.lock.json"));
        assert!(!is_dotnet_lock_file("App.csproj"));
        assert!(!is_dotnet_lock_file("packages.lock.json.fixture"));
    }

    #[test]
    fn filter_orphan_locks_skips_when_manifest_in_same_dir() {
        let dir = PathBuf::from("/proj");
        let manifests = vec![dir.join("App.csproj")];
        let locks = vec![
            dir.join("packages.lock.json"),
            PathBuf::from("/other/packages.lock.json"),
        ];
        let orphans = filter_orphan_locks(&manifests, &locks);
        assert_eq!(orphans, vec![PathBuf::from("/other/packages.lock.json")]);
    }

    #[test]
    fn filter_orphan_locks_returns_orphan_packages_lock() {
        let dir = PathBuf::from("/locks-only");
        let locks = vec![dir.join("packages.lock.json")];
        let orphans = filter_orphan_locks(&[], &locks);
        assert_eq!(orphans, locks);
    }
}
