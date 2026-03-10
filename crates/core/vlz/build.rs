// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct PyProject {
    tool: Option<Tool>,
}

#[derive(serde::Deserialize)]
struct Tool {
    verilyze: Option<Verilyze>,
}

#[derive(serde::Deserialize)]
struct Verilyze {
    #[serde(rename = "line-length")]
    line_length: Option<u64>,
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let pyproject = manifest_dir.join("../../../pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap_or_default();
    let value: u64 = toml::from_str::<PyProject>(&content)
        .ok()
        .and_then(|p| p.tool)
        .and_then(|t| t.verilyze)
        .and_then(|v| v.line_length)
        .unwrap_or(79);

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let constants_path = out_dir.join("constants.rs");
    fs::write(
        constants_path,
        format!("pub const LINE_LENGTH: usize = {};\n", value),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=../../../pyproject.toml");
}
