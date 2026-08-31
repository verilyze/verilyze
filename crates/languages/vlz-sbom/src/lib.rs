// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

//! SBOM inventory plugin: discover and parse CycloneDX / SPDX JSON (FR-038).

mod finder;
mod names;
mod parser;
mod resolver;

pub use finder::SbomManifestFinder;
pub use names::{SBOM_LANGUAGE_NAME, is_sbom_basename, is_sbom_entry_path};
pub use parser::{SbomParser, parse_sbom_bytes, parse_sbom_json};
pub use resolver::SbomResolver;
