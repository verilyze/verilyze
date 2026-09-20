// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

/// Supported PHP Composer lock file basenames (Appendix A).
pub const PHP_LOCK_FILE_NAMES: &[&str] = &["composer.lock"];

/// True when `name` is a supported PHP lock file basename.
pub fn is_php_lock_file(name: &str) -> bool {
    PHP_LOCK_FILE_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_php_lock_file_matches_composer_lock() {
        assert!(is_php_lock_file("composer.lock"));
        assert!(!is_php_lock_file("composer.json"));
        assert!(!is_php_lock_file("composer.lock.fixture"));
    }
}
