// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::io::Write;

use vlz_manifest_finder::ManifestFinder;
use vlz_python::PythonManifestFinder;

#[tokio::test]
async fn find_manifests_in_tree() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("subdir")).unwrap();
    fs::File::create(tmp.join("requirements.txt"))
        .unwrap()
        .write_all(b"foo\n")
        .unwrap();
    fs::File::create(tmp.join("subdir").join("pyproject.toml"))
        .unwrap()
        .write_all(b"[project]\n")
        .unwrap();
    fs::File::create(tmp.join("not-a-manifest.txt")).unwrap();
    // setup.py is deferred (FR-005 / Appendix A); it must NOT appear in results.
    fs::File::create(tmp.join("subdir").join("setup.py"))
        .unwrap()
        .write_all(b"from setuptools import setup\n")
        .unwrap();
    fs::File::create(tmp.join("subdir").join("setup.cfg"))
        .unwrap()
        .write_all(b"[metadata]\n")
        .unwrap();

    let finder = PythonManifestFinder::new();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    let mut want = vec![
        tmp.join("requirements.txt"),
        tmp.join("subdir").join("pyproject.toml"),
        tmp.join("subdir").join("setup.cfg"),
    ];
    want.sort();
    assert_eq!(got, want, "expected {:?}, got {:?}", want, got);
}

#[tokio::test]
async fn with_patterns_only_requirements_fr006() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    fs::create_dir_all(tmp.join("sub")).unwrap();
    fs::File::create(tmp.join("requirements.txt")).unwrap();
    fs::File::create(tmp.join("sub").join("pyproject.toml")).unwrap();
    let finder = PythonManifestFinder::with_patterns(vec![
        r"^requirements\.txt$".to_string(),
    ])
    .unwrap();
    let mut got = finder.find(tmp).await.unwrap();
    got.sort();
    assert_eq!(got, vec![tmp.join("requirements.txt")]);
}
