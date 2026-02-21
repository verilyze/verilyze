// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

/// Find a lock file path for the given manifest, if one exists.
/// Returns the path to the first lock file found in the manifest's directory.
pub fn find_lock_file(manifest_path: &Path) -> Option<PathBuf> {
    let dir = manifest_path.parent()?;
    let name = manifest_path.file_name().and_then(|n| n.to_str())?;

    let lock_candidates: Vec<&str> = match name {
        "pyproject.toml" => vec![
            "pylock.toml",
            "poetry.lock",
            "uv.lock",
        ],
        "Pipfile" => vec!["Pipfile.lock"],
        "requirements.txt" => vec![],
        _ => vec![],
    };

    for candidate in lock_candidates {
        let lock_path = dir.join(candidate);
        if lock_path.exists() && lock_path.is_file() {
            return Some(lock_path);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_lock_file_pipfile_returns_pipfile_lock() {
        let tmp = std::env::temp_dir().join("vlz_lock_discovery_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let pipfile = tmp.join("Pipfile");
        let pipfile_lock = tmp.join("Pipfile.lock");
        std::fs::write(&pipfile, "").unwrap();
        std::fs::write(&pipfile_lock, "{}").unwrap();
        let found = find_lock_file(pipfile.as_path());
        assert_eq!(found.as_deref(), Some(pipfile_lock.as_path()));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
