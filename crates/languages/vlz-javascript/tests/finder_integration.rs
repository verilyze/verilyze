// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::io::Write;

use vlz_javascript::JsManifestFinder;
use vlz_manifest_finder::ManifestFinder;

#[tokio::test]
async fn find_package_json_in_tree() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("packages/app")).unwrap();
    fs::File::create(tmp.join("package.json"))
        .unwrap()
        .write_all(br#"{"name":"root"}"#)
        .unwrap();
    fs::File::create(tmp.join("packages").join("app").join("package.json"))
        .unwrap()
        .write_all(br#"{"name":"app"}"#)
        .unwrap();
    fs::File::create(tmp.join("other.txt")).unwrap();

    let finder = JsManifestFinder::new();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want = vec![
        tmp.join("package.json"),
        tmp.join("packages").join("app").join("package.json"),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[tokio::test]
async fn with_patterns_only_matches_regex_fr006() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("sub")).unwrap();
    fs::File::create(tmp.join("package.json")).unwrap();
    fs::File::create(tmp.join("sub").join("package.json")).unwrap();

    let finder =
        JsManifestFinder::with_patterns(vec![r"^package\.json$".to_string()])
            .unwrap();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want = vec![
        tmp.join("package.json"),
        tmp.join("sub").join("package.json"),
    ];
    want.sort();
    assert_eq!(got, want);
}
