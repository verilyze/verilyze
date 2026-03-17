// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::io::Write;

use vlz_go::GoManifestFinder;
use vlz_manifest_finder::ManifestFinder;

#[tokio::test]
async fn find_go_mod_in_tree() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("pkg/foo")).unwrap();
    fs::File::create(tmp.join("go.mod"))
        .unwrap()
        .write_all(b"module example.com/app\n")
        .unwrap();
    fs::File::create(tmp.join("pkg").join("foo").join("go.mod"))
        .unwrap()
        .write_all(b"module example.com/app/pkg/foo\n")
        .unwrap();
    fs::File::create(tmp.join("other.txt")).unwrap();

    let finder = GoManifestFinder::new();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want = vec![
        tmp.join("go.mod"),
        tmp.join("pkg").join("foo").join("go.mod"),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[tokio::test]
async fn with_patterns_only_matches_regex_fr006() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("sub")).unwrap();
    fs::File::create(tmp.join("go.mod")).unwrap();
    fs::File::create(tmp.join("sub").join("go.mod")).unwrap();

    let finder =
        GoManifestFinder::with_patterns(vec![r"^go\.mod$".to_string()])
            .unwrap();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want = vec![tmp.join("go.mod"), tmp.join("sub").join("go.mod")];
    want.sort();
    assert_eq!(got, want);
}
