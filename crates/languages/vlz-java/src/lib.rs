// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod coordinate;
mod finder;
mod gradle_cli;
mod gradle_root;
mod lock_names;
mod maven_cli;
mod parser;
mod reachability;
mod resolver;

pub use finder::{
    JAVA_MANIFEST_NAMES, JavaManifestFinder, filter_orphan_locks,
};
pub use lock_names::{
    JAVA_LOCK_FILE_NAMES, is_java_lock_file, select_lock_file,
};
pub use parser::{
    JavaManifestParser, parse_gradle_lock,
    parse_gradle_lock_with_declarations, parse_pom_xml,
    parse_pom_xml_with_declarations, parse_version_catalog,
    parse_version_catalog_with_declarations,
};
pub use reachability::JavaTierBAnalyzer;
pub use resolver::{
    JavaManifestKind, JavaResolver, find_java_lock_file,
    java_package_manager_available, java_package_manager_hint, manifest_kind,
};
pub use vlz_db::MAVEN_ECOSYSTEM;
