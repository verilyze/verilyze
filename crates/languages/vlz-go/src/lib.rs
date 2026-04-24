// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod parser;
mod resolver;

pub use finder::{GO_MANIFEST_NAME, GoManifestFinder};
pub use parser::{GoModParser, parse_go_mod};
pub use resolver::{GoResolver, find_go_mod_dir, parse_go_list_m_all};
