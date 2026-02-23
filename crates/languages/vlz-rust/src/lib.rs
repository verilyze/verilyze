// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod parser;
mod resolver;

pub use finder::RustManifestFinder;
pub use parser::{CargoTomlParser, parse_cargo_toml};
pub use resolver::{CargoResolver, find_lock_file, parse_cargo_lock};
