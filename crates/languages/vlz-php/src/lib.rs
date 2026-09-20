// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod lock_names;
mod parser;
mod reachability;
mod resolver;

pub use finder::{PHP_MANIFEST_NAME, PhpManifestFinder, is_php_manifest_name};
pub use lock_names::{PHP_LOCK_FILE_NAMES, is_php_lock_file};
pub use parser::{
    PHP_LOCK_MAX_BYTES, PHP_MANIFEST_MAX_BYTES, PhpManifestParser,
    is_packagist_package_name, parse_composer_json,
    parse_composer_json_with_declarations, parse_composer_lock,
    parse_composer_lock_with_declarations,
};
pub use reachability::PhpTierBAnalyzer;
pub use resolver::{
    PhpResolver, find_php_lock_file, php_package_manager_available,
    php_package_manager_hint,
};
pub use vlz_db::PACKAGIST_ECOSYSTEM;
