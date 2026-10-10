// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod lock_names;
mod parser;
mod resolver;

pub use finder::{DartManifestFinder, is_dart_manifest_name};
pub use lock_names::{
    DART_LOCK_FILE_NAMES, filter_orphan_locks, is_dart_lock_file,
};
pub use parser::{
    DART_LOCK_MAX_BYTES, DART_MANIFEST_MAX_BYTES, DartManifestParser,
    is_pub_dev_hosted_url, is_pub_package_name, parse_pubspec_lock,
    parse_pubspec_lock_with_declarations, parse_pubspec_yaml,
    parse_pubspec_yaml_with_declarations,
};
pub use resolver::{DartResolver, find_dart_lock_file};
pub use vlz_db::PUB_ECOSYSTEM;

/// Stable crate identity for coverage and plugin diagnostics.
pub fn dart_crate_id() -> &'static str {
    "dart"
}

#[cfg(test)]
mod tests {
    #[test]
    fn dart_crate_id_is_dart() {
        assert_eq!(super::dart_crate_id(), "dart");
    }
}
