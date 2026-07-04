// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for Go resolver policy (FR-022, FR-022a).

use vlz_go::{GO_ECOSYSTEM, GoResolver, go_package_manager_available};
use vlz_manifest_parser::{
    DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE, DIRECT_ONLY_REASON_OFFLINE,
    FR_022_TRANSITIVE_ERROR_MESSAGE, ResolutionDepth, ResolveContext,
    Resolver,
};
#[test]
fn go_mod_without_go_exits_fr022_error() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("go.mod"),
        "module example.com/test\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "github.com/gin-gonic/gin".to_string(),
            version: "v1.9.0".to_string(),
            ecosystem: Some(GO_ECOSYSTEM.to_string()),
        }],
        manifest_path: Some(tmp.join("go.mod")),
    };
    let resolver = GoResolver::new();
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
fn go_mod_without_go_fallback_direct_only() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("go.mod"),
        "module example.com/test\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "github.com/gin-gonic/gin".to_string(),
            version: "v1.9.0".to_string(),
            ecosystem: Some(GO_ECOSYSTEM.to_string()),
        }],
        manifest_path: Some(tmp.join("go.mod")),
    };
    let resolver = GoResolver::new();
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

#[tokio::test]
async fn go_mod_offline_direct_only() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("go.mod"),
        "module example.com/test\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "github.com/gin-gonic/gin".to_string(),
            version: "v1.9.0".to_string(),
            ecosystem: Some(GO_ECOSYSTEM.to_string()),
        }],
        manifest_path: Some(tmp.join("go.mod")),
    };
    let resolver = GoResolver::new();
    let ctx = ResolveContext {
        skip_pip_resolution: true,
        ..Default::default()
    };
    let result = resolver.resolve(&graph, &ctx).await.unwrap();
    assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    assert_eq!(result.direct_only_reason, Some(DIRECT_ONLY_REASON_OFFLINE));
}

#[tokio::test]
async fn go_mod_empty_requires_transitive_not_fr022_when_go_available() {
    if !go_package_manager_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::write(tmp.join("go.mod"), "module example.com/test\n").unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![],
        manifest_path: Some(tmp.join("go.mod")),
    };
    let resolver = GoResolver::new();
    let result = resolver
        .resolve(&graph, &ResolveContext::default())
        .await
        .unwrap();
    assert_eq!(result.depth, ResolutionDepth::Transitive);
}
