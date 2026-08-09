// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for JavaScript resolver policy (FR-022, SEC-023).

use vlz_javascript::{JsResolver, NPM_ECOSYSTEM};
use vlz_manifest_parser::{
    DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE, DIRECT_ONLY_REASON_OFFLINE,
    FR_022_TRANSITIVE_ERROR_MESSAGE, ResolutionDepth, ResolveContext,
    Resolver,
};

fn sample_graph(
    root: &std::path::Path,
) -> vlz_manifest_parser::DependencyGraph {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "lodash".to_string(),
            version: "^4.17.21".to_string(),
            ecosystem: Some(NPM_ECOSYSTEM.to_string()),
        }],
        parsed_dependencies: Vec::new(),
        manifest_path: Some(root.join("package.json")),
    }
}

#[test]
fn package_json_without_lock_exits_fr022() {
    let dir = tempfile::tempdir().unwrap();
    let graph = sample_graph(dir.path());
    let resolver = JsResolver::new();
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
fn package_json_without_lock_fallback_direct_only() {
    let dir = tempfile::tempdir().unwrap();
    let graph = sample_graph(dir.path());
    let resolver = JsResolver::new();
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
fn package_json_offline_direct_only() {
    let dir = tempfile::tempdir().unwrap();
    let graph = sample_graph(dir.path());
    let resolver = JsResolver::new();
    let ctx = ResolveContext {
        skip_pip_resolution: true,
        ..Default::default()
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async { resolver.resolve(&graph, &ctx).await })
        .expect("offline direct-only");
    assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    assert_eq!(result.direct_only_reason, Some(DIRECT_ONLY_REASON_OFFLINE));
}

#[test]
fn package_json_with_lock_resolves_transitive() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/lodash": { "version": "4.17.21" }
  }
}"#,
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "lodash".to_string(),
            version: "^4.17.21".to_string(),
            ecosystem: Some(NPM_ECOSYSTEM.to_string()),
        }],
        parsed_dependencies: Vec::new(),
        manifest_path: Some(root.join("package.json")),
    };
    let resolver = JsResolver::new();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            resolver.resolve(&graph, &ResolveContext::default()).await
        })
        .expect("lock resolve");
    assert_eq!(result.depth, ResolutionDepth::Transitive);
    assert!(
        result
            .packages
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.21")
    );
}
