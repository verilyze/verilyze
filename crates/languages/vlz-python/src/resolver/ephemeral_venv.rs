// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ephemeral virtual environment creation for FR-023.
//!
//! When a lock file is not found and pip is available, the resolver creates
//! an ephemeral venv under a secure temp base (XDG_RUNTIME_DIR, TMPDIR, or
//! temp_dir). Uses tempfile for atomic creation and sets 0o700 on Unix.
//! Used by the pip fallback resolver when implemented.

use std::path::PathBuf;
use tempfile::TempDir;

/// Base directory for security-sensitive temp data (ephemeral venvs).
/// Prefers XDG_RUNTIME_DIR, then TMPDIR, then std::env::temp_dir().
fn secure_temp_base() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("TMPDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// Create an ephemeral directory for a virtual environment (FR-023).
/// Uses tempfile for atomic creation; sets 0o700 on Unix for owner-only access.
/// Caller must keep the returned TempDir in scope until the venv is no longer needed.
pub fn create_ephemeral_venv_dir() -> std::io::Result<TempDir> {
    let dir = tempfile::tempdir_in(secure_temp_base())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path(),
            std::fs::Permissions::from_mode(0o700),
        )?;
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ephemeral_venv_dir_succeeds() {
        temp_env::with_var("XDG_RUNTIME_DIR", None::<&str>, || {
            let dir = create_ephemeral_venv_dir().expect("create dir");
            assert!(dir.path().exists());
            assert!(dir.path().is_dir());
        });
    }

    #[cfg(unix)]
    #[test]
    fn create_ephemeral_venv_dir_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        temp_env::with_var("XDG_RUNTIME_DIR", None::<&str>, || {
            let dir = create_ephemeral_venv_dir().expect("create dir");
            let meta = std::fs::metadata(dir.path()).expect("metadata");
            let mode = meta.permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "dir should be 0o700");
        });
    }
}
