// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod lock_names;
mod parser;
mod reachability;
mod resolver;

pub use finder::{
    RUBY_MANIFEST_NAMES, RubyManifestFinder, is_ruby_manifest_name,
};
pub use lock_names::{
    RUBY_LOCK_FILE_NAMES, is_ruby_lock_file, lock_name_for_manifest,
    lock_names_for_manifest, manifest_name_for_lock,
};
pub use parser::{
    RUBY_LOCK_MAX_BYTES, RUBY_MANIFEST_MAX_BYTES, RubyManifestParser,
    parse_gemfile, parse_gemfile_lock, parse_gemfile_lock_with_declarations,
    parse_gemfile_with_declarations, parse_gemspec,
    parse_gemspec_with_declarations,
};
pub use reachability::RubyTierBAnalyzer;
pub use resolver::{
    RubyResolver, find_ruby_lock_file, ruby_package_manager_available,
    ruby_package_manager_hint,
};
pub use vlz_db::RUBYGEMS_ECOSYSTEM;
