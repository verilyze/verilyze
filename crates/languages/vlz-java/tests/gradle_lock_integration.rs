// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_db::MAVEN_ECOSYSTEM;
use vlz_java::{JavaManifestParser, parse_gradle_lock};
use vlz_manifest_parser::Parser;

#[test]
fn lock_includes_test_classpath_packages() {
    let content = r#"# sample
org.junit:junit:4.13.2=testCompileClasspath
com.app:core:1.0=compileClasspath
empty=annotationProcessor
"#;
    let pkgs = parse_gradle_lock(content).unwrap();
    assert_eq!(pkgs.len(), 2);
    assert!(pkgs.iter().any(|p| p.name == "org.junit:junit"));
    assert_eq!(pkgs[0].ecosystem.as_deref(), Some(MAVEN_ECOSYSTEM));
}

#[tokio::test]
async fn parser_reads_lock_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("gradle.lockfile");
    std::fs::write(
        &lock,
        "com.google.guava:guava:33.0.0-jre=compileClasspath\n",
    )
    .unwrap();
    let graph = JavaManifestParser::new().parse(&lock).await.unwrap();
    assert_eq!(graph.packages.len(), 1);
    assert_eq!(graph.packages[0].name, "com.google.guava:guava");
}
