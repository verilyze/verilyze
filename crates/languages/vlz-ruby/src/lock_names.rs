// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

/// Supported Ruby lock file basenames.
pub const RUBY_LOCK_FILE_NAMES: &[&str] = &["Gemfile.lock", "gems.locked"];

/// True when `name` is a supported Ruby lock basename.
pub fn is_ruby_lock_file(name: &str) -> bool {
    RUBY_LOCK_FILE_NAMES.contains(&name)
}

/// Return the exact lock basename paired with a manifest.
pub fn lock_name_for_manifest(manifest: &Path) -> Option<&'static str> {
    lock_names_for_manifest(manifest).and_then(|names| names.first().copied())
}

/// Lock basenames to try for a manifest (ordered preference).
pub fn lock_names_for_manifest(
    manifest: &Path,
) -> Option<&'static [&'static str]> {
    let name = manifest.file_name()?.to_str()?;
    match name {
        "Gemfile" => Some(&["Gemfile.lock"]),
        "gems.rb" => Some(&["gems.locked"]),
        // Prefer Gemfile.lock, then gems.locked for gem libraries.
        _ if name.ends_with(".gemspec") => {
            Some(&["Gemfile.lock", "gems.locked"])
        }
        _ => None,
    }
}

/// Return the conventional manifest basename paired with a lock.
pub fn manifest_name_for_lock(lock_name: &str) -> Option<&'static str> {
    match lock_name {
        "Gemfile.lock" => Some("Gemfile"),
        "gems.locked" => Some("gems.rb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_are_exact() {
        assert_eq!(
            lock_name_for_manifest(Path::new("Gemfile")),
            Some("Gemfile.lock")
        );
        assert_eq!(
            lock_name_for_manifest(Path::new("gems.rb")),
            Some("gems.locked")
        );
        assert_eq!(
            lock_name_for_manifest(Path::new("demo.gemspec")),
            Some("Gemfile.lock")
        );
        assert_eq!(manifest_name_for_lock("gems.locked"), Some("gems.rb"));
        assert!(!is_ruby_lock_file("Gemfile"));
    }
}
