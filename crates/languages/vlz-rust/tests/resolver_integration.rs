// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for Rust resolver policy (FR-022, FR-022a).

use vlz_manifest_parser::{
    DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE, FR_022_TRANSITIVE_ERROR_MESSAGE,
    ResolutionDepth, ResolveContext, Resolver,
};
use vlz_rust::CargoResolver;

#[test]
fn cargo_toml_without_cargo_exits_fr022_error() {
    let dir = tempfile::Builder::new()
        .prefix("vlz-rust-resolver-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("Cargo.toml"),
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("crates.io".to_string()),
        }],
        manifest_path: Some(tmp.join("Cargo.toml")),
    };
    let resolver = CargoResolver::new();
    let ctx = ResolveContext::default();
    temp_env::with_var("PATH", Some(""), || {
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
    });
}

#[test]
fn cargo_toml_without_cargo_fallback_direct_only() {
    let dir = tempfile::Builder::new()
        .prefix("vlz-rust-resolver-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("Cargo.toml"),
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("crates.io".to_string()),
        }],
        manifest_path: Some(tmp.join("Cargo.toml")),
    };
    let resolver = CargoResolver::new();
    let ctx = ResolveContext {
        allow_direct_only_fallback: true,
        ..Default::default()
    };
    temp_env::with_var("PATH", Some(""), || {
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
    });
}

/// Live cargo tests contact crates.io; gate behind env var for CI without network.
#[tokio::test]
#[ignore = "requires VLZ_TEST_LIVE_CARGO=1 and network"]
async fn live_cargo_metadata_minimal_crate() {
    if std::env::var("VLZ_TEST_LIVE_CARGO").ok().as_deref() != Some("1") {
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("vlz-rust-resolver-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("Cargo.toml"),
        r#"[package]
name = "vlz-live-test"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![],
        manifest_path: Some(tmp.join("Cargo.toml")),
    };
    let resolver = CargoResolver::new();
    let result = resolver
        .resolve(&graph, &ResolveContext::default())
        .await
        .unwrap();
    assert_eq!(result.depth, ResolutionDepth::Transitive);
}
