// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mem-cache + portable JSON ignore integration.
//!
//! Run with:
//! `cargo test -p vlz --no-default-features --features "mem,python,testing" --test mem_cache_ignore`

#![cfg(all(feature = "mem", feature = "python", feature = "testing"))]

mod support;

use support::{ensure_registries_for_run, run_async, with_temp_xdg};

#[test]
fn mem_scan_applies_json_ignore_and_creates_no_cache_redb() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        let ignore_path = vlz::config::default_ignore_path();
        let fp = vlz::registry::open_ignore_db(ignore_path.clone())
            .expect("open ignore");
        fp.mark("CVE-2024-TEST", "from json", None).expect("mark");
        drop(fp);

        let dir = tempfile::tempdir().expect("tempdir");
        support::write_requirements_with_pylock(dir.path(), "pkg", "1.0.0");
        let root = dir.path().to_str().unwrap();

        // Provider returns CVE-2024-TEST; FP filter should drop it -> exit 0.
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            vlz::mocks::CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--provider",
            "cve_returning",
            "--fp-exit-code",
            "77",
        ]);
        assert_eq!(
            code, 77,
            "marked CVE should be filtered; fp_exit_code applies"
        );

        let cache_home = std::env::var("XDG_CACHE_HOME").unwrap();
        let unexpected = std::path::Path::new(&cache_home)
            .join("verilyze")
            .join("vlz-cache.redb");
        assert!(
            !unexpected.exists(),
            "mem build must not create vlz-cache.redb"
        );
        assert!(
            ignore_path.exists(),
            "JSON ignore file should exist after mark"
        );
    });
}

#[test]
fn mem_rejects_explicit_cache_db_with_exit_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let bogus = dir.path().join("cache.redb");
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--cache-db",
                bogus.to_str().unwrap(),
            ]),
            2,
            "explicit --cache-db must exit 2 on mem builds"
        );
    });
}

#[test]
fn mem_rejects_vlz_cache_db_env_with_exit_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let bogus = dir.path().join("from-env.redb");
        temp_env::with_var("VLZ_CACHE_DB", Some(bogus.as_os_str()), || {
            assert_eq!(
                run_async(&["scan", root, "--offline", "--benchmark"]),
                2,
                "VLZ_CACHE_DB must exit 2 on mem builds"
            );
        });
    });
}

#[test]
fn mem_rejects_config_cache_db_with_exit_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let bogus = dir.path().join("from-conf.redb");
        let conf = dir.path().join("verilyze.conf");
        std::fs::write(&conf, format!("cache_db = \"{}\"\n", bogus.display()))
            .expect("write conf");
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--config",
                conf.to_str().unwrap(),
            ]),
            2,
            "config cache_db must exit 2 on mem builds"
        );
    });
}

#[test]
fn mem_rejects_legacy_redb_ignore_path_with_exit_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let legacy = dir.path().join("vlz-ignore.redb");
        // Touch a placeholder so path looks like a legacy file.
        std::fs::write(&legacy, b"not-a-real-redb").expect("touch legacy");
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--ignore-db",
                legacy.to_str().unwrap(),
            ]),
            2,
            "legacy .redb ignore path must exit 2 on mem builds"
        );
    });
}
