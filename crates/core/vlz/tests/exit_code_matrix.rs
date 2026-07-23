// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! FR-010 / DOC-004: authoritative mapping of exit codes to scripted scenarios.
//!
//! Each `exit_*` test documents one matrix row. The `exit_code_matrix_is_complete`
//! test ensures every FR-010 code has a named scenario.

mod support;

use support::{run_async, with_temp_xdg, write_requirements_with_pylock};
use vlz::mocks::{CveReturningProvider, FailingCveProvider};

/// FR-010 exit codes exercised by this module (exit 1: `vlz db verify` integrity
/// failure and unhandled panic via subprocess through `main.rs`).
const FR_010_MATRIX: &[(i32, &str)] = &[
    (0, "exit_0_scan_success"),
    (1, "exit_1_db_verify_integrity_failure"),
    (2, "exit_2_unknown_provider"),
    (3, "exit_3_missing_package_manager"),
    (4, "exit_4_resolution_failed"),
    (5, "exit_5_cve_provider_fetch_failed"),
    (6, "exit_6_offline_cache_miss"),
    (86, "exit_86_cve_found"),
];

#[test]
fn exit_code_matrix_is_complete() {
    let documented: Vec<i32> =
        FR_010_MATRIX.iter().map(|(code, _)| *code).collect();
    for code in [0, 1, 2, 3, 4, 5, 6, 86] {
        assert!(
            documented.contains(&code),
            "FR-010 exit code {code} must have a named test in FR_010_MATRIX"
        );
    }
}

#[test]
fn exit_0_scan_success() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&["scan", root, "--offline", "--benchmark"]),
            0,
            "empty tree scan completes successfully"
        );
    });
}

#[test]
fn exit_1_db_verify_integrity_failure() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        vlz::registry::clear_db_backends();
        vlz::registry::register(vlz::registry::Plugin::DatabaseBackend(
            Box::new(vlz::mocks::FailingDbBackend::new()),
        ));
        assert_eq!(
            run_async(&["db", "verify"]),
            1,
            "integrity check failure (FR-033)"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn exit_1_panic_via_subprocess() {
    use std::process::Command;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    write_requirements_with_pylock(proj.as_path(), "pkg", "1.0");
    let root_str = proj.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args([
            "scan",
            root_str,
            "--provider",
            "panicking",
            "--format",
            "plain",
        ])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("RUST_LOG", "off")
        .output()
        .expect("run vlz");

    assert_eq!(
        out.status.code(),
        Some(1),
        "unhandled panic must exit 1 via main.rs boundary (stderr={})",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn exit_2_unknown_provider() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--provider",
                "nonexistentprovider",
                "--offline",
            ]),
            2,
            "invalid provider name (FR-019)"
        );
    });
}

#[test]
fn exit_3_missing_package_manager() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let path_without_pip = empty_dir.path().to_string_lossy().into_owned();
        temp_env::with_var("PATH", Some(&path_without_pip), || {
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--package-manager-required",
                ]),
                3,
                "missing required package manager (FR-024)"
            );
        });
    });
}

#[cfg(feature = "python")]
#[test]
fn exit_4_resolution_failed() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_resolvers();
        vlz::registry::register(vlz::registry::Plugin::Resolver(Box::new(
            vlz::mocks::FailingResolver::new(),
        )));
        assert_eq!(
            run_async(&["scan", root, "--offline"]),
            4,
            "blocking manifest resolution failure (FR-022)"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn exit_5_cve_provider_fetch_failed() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            FailingCveProvider::new(),
        )));
        assert_eq!(
            run_async(&["scan", root]),
            5,
            "CVE provider fetch failure must not false-negative (FR-010)"
        );
    });
}

#[test]
fn exit_6_offline_cache_miss() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&["scan", root, "--offline"]),
            6,
            "offline mode with uncached CVE lookup (FR-031)"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn exit_86_cve_found() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));
        assert_eq!(
            run_async(&["scan", root, "--provider", "cve_returning"]),
            86,
            "CVE meeting threshold (FR-014, default exit 86)"
        );
    });
}
