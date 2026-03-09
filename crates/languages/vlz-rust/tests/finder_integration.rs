// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::io::Write;

use vlz_manifest_finder::ManifestFinder;
use vlz_rust::RustManifestFinder;

#[tokio::test]
async fn find_cargo_toml_in_tree() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("crates/foo")).unwrap();
    fs::File::create(tmp.join("Cargo.toml"))
        .unwrap()
        .write_all(b"[package]\nname = \"root\"\n")
        .unwrap();
    fs::File::create(tmp.join("crates").join("foo").join("Cargo.toml"))
        .unwrap()
        .write_all(b"[package]\nname = \"foo\"\n")
        .unwrap();
    fs::File::create(tmp.join("other.txt")).unwrap();

    let finder = RustManifestFinder::new();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want = vec![
        tmp.join("Cargo.toml"),
        tmp.join("crates").join("foo").join("Cargo.toml"),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[tokio::test]
async fn with_patterns_only_matches_regex_fr006() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("sub")).unwrap();
    fs::File::create(tmp.join("Cargo.toml")).unwrap();
    fs::File::create(tmp.join("sub").join("Cargo.toml")).unwrap();

    let finder =
        RustManifestFinder::with_patterns(vec![r"^Cargo\.toml$".to_string()])
            .unwrap();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want =
        vec![tmp.join("Cargo.toml"), tmp.join("sub").join("Cargo.toml")];
    want.sort();
    assert_eq!(got, want);
}
