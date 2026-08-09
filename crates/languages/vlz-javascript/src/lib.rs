// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod lock_names;
mod parser;
mod reachability;
mod resolver;

pub use finder::{JS_MANIFEST_NAME, JsManifestFinder};
pub use lock_names::{JS_LOCK_FILE_NAMES, is_js_lock_file, select_lock_file};
pub use parser::{
    JsManifestParser, PackageJsonMeta, parse_bun_lock, parse_npm_lock,
    parse_package_json, parse_package_json_with_meta, parse_pnpm_lock,
    parse_yarn_lock,
};
pub use reachability::JsTierBAnalyzer;
pub use resolver::{
    JsResolver, find_js_lock_file, js_package_manager_available,
};
pub use vlz_db::NPM_ECOSYSTEM;
