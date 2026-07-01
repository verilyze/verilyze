// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for Python resolver policy (FR-022, FR-022a, SEC-023).

use vlz_manifest_parser::{ResolutionDepth, ResolveContext, Resolver};
use vlz_python::{
    DIRECT_ONLY_REASON_EXEC_DISABLED, DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE,
    DIRECT_ONLY_REASON_OFFLINE, DirectOnlyResolver,
    FR_022_TRANSITIVE_ERROR_MESSAGE,
};

#[test]
fn requirements_txt_without_pip_exits_fr022_error() {
    let dir = tempfile::tempdir().unwrap();
    let req = dir.path().join("requirements.txt");
    std::fs::write(&req, b"requests>=2.0\n").unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "requests".to_string(),
            version: "*".to_string(),
            ecosystem: Some("PyPI".to_string()),
        }],
        manifest_path: Some(req),
    };
    let resolver = DirectOnlyResolver::new();
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

#[tokio::test]
async fn setup_py_secure_default_is_direct_only_with_reason() {
    let dir = tempfile::tempdir().unwrap();
    let setup = dir.path().join("setup.py");
    std::fs::write(
        &setup,
        b"from setuptools import setup\nsetup(name='x', install_requires=['requests'])\n",
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "x".to_string(),
            version: "0.0.0".to_string(),
            ecosystem: Some("PyPI".to_string()),
        }],
        manifest_path: Some(setup),
    };
    let resolver = DirectOnlyResolver::new();
    let result = resolver
        .resolve(&graph, &ResolveContext::default())
        .await
        .unwrap();
    assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    assert_eq!(
        result.direct_only_reason,
        Some(DIRECT_ONLY_REASON_EXEC_DISABLED)
    );
}

#[tokio::test]
async fn offline_mode_direct_only_for_pyproject() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pyproject.toml");
    std::fs::write(
        &manifest,
        b"[project]\nname = \"demo\"\ndependencies = [\"requests\"]\n",
    )
    .unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "requests".to_string(),
            version: "*".to_string(),
            ecosystem: Some("PyPI".to_string()),
        }],
        manifest_path: Some(manifest),
    };
    let resolver = DirectOnlyResolver::new();
    let ctx = ResolveContext {
        skip_pip_resolution: true,
        ..Default::default()
    };
    let result = resolver.resolve(&graph, &ctx).await.unwrap();
    assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    assert_eq!(result.direct_only_reason, Some(DIRECT_ONLY_REASON_OFFLINE));
}

/// Live pip tests contact PyPI; gate behind env var for CI without network.
#[tokio::test]
#[ignore = "requires VLZ_TEST_LIVE_PIP=1 and network"]
async fn live_pip_lock_requirements_only_binary() {
    if std::env::var("VLZ_TEST_LIVE_PIP").ok().as_deref() != Some("1") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let req = dir.path().join("requirements.txt");
    std::fs::write(&req, b"certifi==2024.7.4\n").unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "certifi".to_string(),
            version: "2024.7.4".to_string(),
            ecosystem: Some("PyPI".to_string()),
        }],
        manifest_path: Some(req),
    };
    let resolver = DirectOnlyResolver::new();
    let result = resolver
        .resolve(&graph, &ResolveContext::default())
        .await
        .unwrap();
    assert_eq!(result.depth, ResolutionDepth::Transitive);
    assert!(result.packages.iter().any(|p| p.name == "certifi"));
}

#[test]
fn requirements_txt_without_pip_fallback_direct_only() {
    let dir = tempfile::tempdir().unwrap();
    let req = dir.path().join("requirements.txt");
    std::fs::write(&req, b"requests>=2.0\n").unwrap();
    let graph = vlz_manifest_parser::DependencyGraph {
        packages: vec![vlz_db::Package {
            name: "requests".to_string(),
            version: "*".to_string(),
            ecosystem: Some("PyPI".to_string()),
        }],
        manifest_path: Some(req),
    };
    let resolver = DirectOnlyResolver::new();
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
