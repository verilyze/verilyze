// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct BuildMetadata {
    tool: Option<Tool>,
}

#[derive(serde::Deserialize)]
struct Tool {
    verilyze: Option<Verilyze>,
    #[serde(rename = "vlz-headers")]
    vlz_headers: Option<VlzHeaders>,
}

#[derive(serde::Deserialize)]
struct Verilyze {
    #[serde(rename = "line-length")]
    line_length: Option<u64>,
}

#[derive(serde::Deserialize)]
struct VlzHeaders {
    default_copyright: Option<String>,
    default_license: Option<String>,
}

fn main() {
    const DEFAULT_LINE_LENGTH: u64 = 79;
    const DEFAULT_COPYRIGHT: &str = "The verilyze contributors";
    const DEFAULT_LICENSE: &str = "GPL-3.0-or-later";

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let metadata_path = manifest_dir.join("build-metadata.toml");
    let content = fs::read_to_string(&metadata_path).unwrap_or_default();
    let parsed = toml::from_str::<BuildMetadata>(&content).ok();
    let line_length: u64 = parsed
        .as_ref()
        .and_then(|p| p.tool.as_ref())
        .and_then(|t| t.verilyze.as_ref())
        .and_then(|v| v.line_length)
        .unwrap_or(DEFAULT_LINE_LENGTH);
    let spdx_copyright = parsed
        .as_ref()
        .and_then(|p| p.tool.as_ref())
        .and_then(|t| t.vlz_headers.as_ref())
        .and_then(|h| h.default_copyright.clone())
        .unwrap_or_else(|| DEFAULT_COPYRIGHT.to_string());
    let spdx_license = parsed
        .as_ref()
        .and_then(|p| p.tool.as_ref())
        .and_then(|t| t.vlz_headers.as_ref())
        .and_then(|h| h.default_license.clone())
        .unwrap_or_else(|| DEFAULT_LICENSE.to_string());

    let constants = format!(
        "pub const LINE_LENGTH: usize = {line_length};\n\
         pub const MANPAGE_SPDX_COPYRIGHT: &str = {copyright:?};\n\
         pub const MANPAGE_SPDX_LICENSE: &str = {license:?};\n",
        line_length = line_length,
        copyright = spdx_copyright,
        license = spdx_license
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let constants_path = out_dir.join("constants.rs");
    fs::write(constants_path, constants).unwrap();

    let man_src = manifest_dir.join("assets/vlz.1");
    let man_dst = out_dir.join("embedded_vlz.1");
    let man_content = fs::read_to_string(man_src).unwrap_or_default();
    fs::write(man_dst, man_content).unwrap();

    println!("cargo:rerun-if-changed=build-metadata.toml");
    println!("cargo:rerun-if-changed=assets/vlz.1");
}
