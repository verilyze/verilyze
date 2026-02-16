// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

pub mod cli;
pub mod config;
pub mod registry;
pub mod run;

#[cfg(any(test, feature = "testing"))]
pub mod mocks;

pub use run::run;
