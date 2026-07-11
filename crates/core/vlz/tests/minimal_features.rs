// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Coverage for `run.rs` paths that only compile without default features
//! (`redb`, `docs`). Run with:
//! `cargo test -p vlz --no-default-features --features testing --test minimal_features`

#[cfg(any(not(feature = "redb"), not(feature = "docs")))]
mod support;

#[cfg(any(not(feature = "redb"), not(feature = "docs")))]
use support::{run_async, with_temp_xdg};

/// Without `redb`, `ensure_default_db_backend_with_path` is not called, so an
/// empty registry yields the "No DatabaseBackend" error (exit 2).
#[cfg(not(feature = "redb"))]
#[test]
fn scan_without_db_backend_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        vlz::registry::clear_db_backends();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&["scan", root, "--offline", "--benchmark"]),
            2,
            "empty DatabaseBackend registry must exit 2"
        );
    });
}

/// Without `redb`, `vlz fp` returns a clear feature-gated error (exit 2).
#[cfg(not(feature = "redb"))]
#[test]
fn fp_without_redb_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        // Register a mock backend so run() reaches the Fp arm (redb gate).
        vlz::registry::clear_db_backends();
        vlz::registry::register(vlz::registry::Plugin::DatabaseBackend(
            Box::new(vlz::mocks::FailingDbBackend::new()),
        ));
        assert_eq!(
            run_async(&["fp", "mark", "CVE-2024-1", "--comment", "x"]),
            2,
            "vlz fp requires the redb feature"
        );
    });
}

/// Without `docs`, `vlz help` exits 2 with MOD-009 message.
#[cfg(not(feature = "docs"))]
#[test]
fn help_without_docs_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(
            run_async(&["help"]),
            2,
            "vlz help without docs feature must exit 2"
        );
    });
}

/// Placeholder so the test binary builds under default features.
#[cfg(all(feature = "redb", feature = "docs"))]
#[test]
fn minimal_features_tests_skipped_under_default_features() {
    // Exercised via: cargo test -p vlz --no-default-features --features testing
}
