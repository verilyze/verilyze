// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_manifest_parser::Parser;
use vlz_rust::CargoTomlParser;

#[tokio::test]
async fn parse_simple_cargo_toml() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::create_dir_all(tmp).unwrap();
    std::fs::write(
        tmp.join("Cargo.toml"),
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["rt"] }
"#,
    )
    .unwrap();

    let parser = CargoTomlParser::new();
    let graph = parser.parse(&tmp.join("Cargo.toml")).await.unwrap();
    assert_eq!(graph.packages.len(), 2);
    assert!(graph.packages.iter().any(|p| p.name == "serde"));
    assert!(graph.packages.iter().any(|p| p.name == "tokio"));
}
