// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! FR-006: custom `[java].regex` discovers only matching basenames.

use vlz_java::JavaManifestFinder;
use vlz_manifest_finder::ManifestFinder;

#[tokio::test]
async fn java_regex_only_matches_pom() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("pom.xml"), "<project/>").unwrap();
    std::fs::write(root.join("build.gradle"), "plugins {}").unwrap();
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(root.join("gradle/libs.versions.toml"), "[versions]\n")
        .unwrap();

    let finder =
        JavaManifestFinder::with_patterns(vec![r"^pom\.xml$".to_string()])
            .unwrap();
    let found = finder.find(root).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0], root.join("pom.xml"));
}
