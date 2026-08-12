// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for Java resolver policy (FR-022, SEC-023).

use vlz_db::MAVEN_ECOSYSTEM;
use vlz_java::JavaResolver;
use vlz_manifest_parser::{
    DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE, FR_022_TRANSITIVE_ERROR_MESSAGE,
    ResolutionDepth, ResolveContext, Resolver,
};

fn pom_graph(root: &std::path::Path) -> vlz_manifest_parser::DependencyGraph {
    std::fs::write(
        root.join("pom.xml"),
        r#"<project><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>33.0.0-jre</version></dependency></dependencies></project>"#,
    )
    .unwrap();
    vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "com.google.guava:guava".into(),
            version: "33.0.0-jre".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        }],
        parsed_dependencies: Vec::new(),
        manifest_path: Some(root.join("pom.xml")),
    }
}

fn catalog_graph(
    root: &std::path::Path,
) -> vlz_manifest_parser::DependencyGraph {
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(
        root.join("gradle/libs.versions.toml"),
        r#"
[versions]
guava = "33.0.0-jre"

[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
"#,
    )
    .unwrap();
    vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "com.google.guava:guava".into(),
            version: "33.0.0-jre".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        }],
        parsed_dependencies: Vec::new(),
        manifest_path: Some(root.join("gradle/libs.versions.toml")),
    }
}

#[test]
fn pom_without_lock_exits_fr022() {
    let dir = tempfile::tempdir().unwrap();
    let graph = pom_graph(dir.path());
    let resolver = JavaResolver::new();
    let ctx = ResolveContext::default();
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async { resolver.resolve(&graph, &ctx).await })
        .unwrap_err();
    assert!(
        err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE),
        "expected FR-022 message, got: {err}"
    );
}

#[test]
fn catalog_only_without_lock_exits_fr022() {
    let dir = tempfile::tempdir().unwrap();
    let graph = catalog_graph(dir.path());
    let resolver = JavaResolver::new();
    let ctx = ResolveContext::default();
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async { resolver.resolve(&graph, &ctx).await })
        .unwrap_err();
    assert!(
        err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE),
        "expected FR-022 message, got: {err}"
    );
}

#[test]
fn pom_without_lock_fallback_direct_only() {
    let dir = tempfile::tempdir().unwrap();
    let graph = pom_graph(dir.path());
    let resolver = JavaResolver::new();
    let ctx = ResolveContext {
        allow_direct_only_fallback: true,
        ..Default::default()
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async { resolver.resolve(&graph, &ctx).await })
        .expect("direct-only fallback");
    assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    assert_eq!(
        result.direct_only_reason,
        Some(DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE)
    );
}

#[test]
fn gradle_lock_resolves_transitive() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("build.gradle"), "dependencies {}").unwrap();
    std::fs::write(
        root.join("gradle.lockfile"),
        "org.springframework:spring-beans:5.0.5.RELEASE=compileClasspath\norg.springframework:spring-core:5.0.5.RELEASE=testCompileClasspath\n",
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "org.springframework:spring-beans".into(),
            version: "5.0.5.RELEASE".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        }],
        parsed_dependencies: Vec::new(),
        manifest_path: Some(root.join("build.gradle")),
    };
    let resolver = JavaResolver::new();
    let ctx = ResolveContext {
        scan_root: Some(root.to_path_buf()),
        ..Default::default()
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async { resolver.resolve(&graph, &ctx).await })
        .expect("lock resolve");
    assert_eq!(result.depth, ResolutionDepth::Transitive);
    assert!(
        result
            .packages
            .iter()
            .any(|p| p.name == "org.springframework:spring-core")
    );
}

#[test]
fn gradle_lock_as_manifest_entry_is_transitive() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("gradle.lockfile");
    std::fs::write(&lock, "com.example:lib:1.0.0=compileClasspath\n").unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "com.example:lib".into(),
            version: "1.0.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        }],
        parsed_dependencies: Vec::new(),
        manifest_path: Some(lock),
    };
    let resolver = JavaResolver::new();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            resolver.resolve(&graph, &ResolveContext::default()).await
        })
        .expect("orphan lock");
    assert_eq!(result.depth, ResolutionDepth::Transitive);
}
