// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use vlz_java::{JavaManifestKind, java_package_manager_hint, manifest_kind};

#[test]
fn per_manifest_pm_kind_maven_vs_gradle() {
    assert_eq!(
        manifest_kind(Path::new("/proj/pom.xml")),
        JavaManifestKind::Maven
    );
    assert_eq!(
        manifest_kind(Path::new("/proj/build.gradle")),
        JavaManifestKind::Gradle
    );
    assert_eq!(
        manifest_kind(Path::new("/proj/build.gradle.kts")),
        JavaManifestKind::Gradle
    );
    assert_eq!(
        manifest_kind(Path::new("/proj/gradle.lockfile")),
        JavaManifestKind::GradleLock
    );
}

#[test]
fn fr024_hints_differ_by_manifest_kind() {
    let maven = java_package_manager_hint(Path::new("pom.xml"));
    let gradle = java_package_manager_hint(Path::new("build.gradle"));
    assert!(maven.contains("Maven"));
    assert!(gradle.contains("Gradle"));
    assert_ne!(maven, gradle);
}
