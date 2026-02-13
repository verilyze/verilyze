// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod parser;
mod resolver;

pub use finder::PythonManifestFinder;
pub use parser::{parse_requirements_txt, RequirementsTxtParser};
pub use resolver::DirectOnlyResolver;
