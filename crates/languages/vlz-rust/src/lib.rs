// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod parser;
mod reachability;
mod resolver;

pub use finder::{RUST_MANIFEST_NAME, RustManifestFinder};
pub use parser::{CargoTomlParser, parse_cargo_toml};
pub use reachability::RustTierBAnalyzer;
pub use resolver::{CargoResolver, find_lock_file, parse_cargo_lock};
