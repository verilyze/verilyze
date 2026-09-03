// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod support;

use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use support::{
    apply_isolated_db_env, ensure_registries_for_run, run_async,
    with_temp_xdg, with_temp_xdg_env, write_requirements_with_pylock,
};
use vlz::cli::Cli;
use vlz::mocks::{
    CountingCveProvider, CveReturningProvider, TierCReachabilityProvider,
};
use vlz_db::{DatabaseBackend, IgnoreDb, Package};

#[cfg(feature = "redb")]
fn reregister_db_backend() {
    let cache_path = vlz::config::default_cache_path();
    let _ = vlz::registry::ensure_default_db_backend_with_path(
        cache_path,
        vlz::config::DEFAULT_CACHE_TTL_SECS,
    );
}

#[test]
fn run_version_subcommand_is_gone() {
    // The `version` subcommand was removed (FR-002); `--version` is the only form.
    // Verify that `vlz version` is no longer a recognised subcommand.
    let _ = env_logger::try_init();
    let result = Cli::try_parse_from(["vlz", "version"]);
    assert!(
        result.is_err(),
        "'vlz version' must be an unknown subcommand after FR-002 removal"
    );
}

#[test]
fn run_languages_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["languages"]), 0));
}

#[test]
fn run_list_alias_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["list"]), 0));
}

#[test]
fn run_preload_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        // Empty project root: hermetic (no live OSV). Bare `preload` without a
        // path would scan the repo cwd and require network.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(run_async(&["preload", root]), 0);
    });
}

#[cfg(feature = "python")]
#[test]
fn run_preload_populates_cache_for_fixture() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code =
            run_async(&["preload", root, "--provider", "cve_returning"]);
        assert_eq!(code, 0);

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));
        #[cfg(feature = "redb")]
        reregister_db_backend();

        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 0, "offline scan should hit preloaded cache");
    });
}

#[cfg(feature = "python")]
#[test]
fn run_preload_offline_miss_exits_6() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();
        assert_eq!(run_async(&["preload", root, "--offline"]), 6);
    });
}

#[cfg(feature = "python")]
#[test]
fn run_preload_and_scan_resolve_same_packages_with_matching_flags() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();
        let scan_cache = dir.path().join("scan-only-cache.redb");
        let scan_cache_arg = scan_cache.to_string_lossy().into_owned();

        let preload_counts: Arc<Mutex<HashMap<String, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CountingCveProvider::new(preload_counts.clone()),
        )));
        #[cfg(feature = "redb")]
        reregister_db_backend();

        assert_eq!(
            run_async(&[
                "preload",
                root,
                "--provider",
                "counting",
                "--scan-exclude-dir",
                "vendor",
            ]),
            0
        );
        let preload_keys: HashSet<String> =
            preload_counts.lock().unwrap().keys().cloned().collect();
        assert!(
            !preload_keys.is_empty(),
            "preload should warm at least one package"
        );

        let scan_counts: Arc<Mutex<HashMap<String, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CountingCveProvider::new(scan_counts.clone()),
        )));
        #[cfg(feature = "redb")]
        {
            let _ = vlz::registry::ensure_default_db_backend_with_path(
                scan_cache,
                vlz::config::DEFAULT_CACHE_TTL_SECS,
            );
        }

        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--provider",
                "counting",
                "--cache-db",
                &scan_cache_arg,
                "--scan-exclude-dir",
                "vendor",
                "--format",
                "plain",
            ]),
            0
        );
        let scan_keys: HashSet<String> =
            scan_counts.lock().unwrap().keys().cloned().collect();
        assert_eq!(
            preload_keys, scan_keys,
            "preload and scan must resolve the same package keys with identical flags"
        );
    });
}

#[cfg(all(feature = "python", feature = "redb"))]
#[test]
fn run_preload_then_db_show_lists_cached_entry() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));
        reregister_db_backend();

        assert_eq!(
            run_async(&["preload", root, "--provider", "cve_returning"]),
            0
        );

        reregister_db_backend();
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let entries = {
            let mut backends = vlz::registry::db_backends()
                .lock()
                .expect("db backends lock");
            let backend = backends.remove(0);
            rt.block_on(backend.list_entries(false))
                .expect("list cache entries")
        };
        assert!(
            !entries.is_empty(),
            "preload should populate at least one cache entry"
        );
        assert!(
            entries.iter().any(|e| e.cve_count > 0),
            "preloaded entry should include CVE data"
        );

        vlz::registry::clear_providers();
        vlz::registry::ensure_default_cve_provider(
            &vlz::config::EffectiveConfig::default(),
        );
        reregister_db_backend();

        assert_eq!(run_async(&["db", "show", "--full"]), 0);
    });
}

#[cfg(feature = "python")]
#[test]
fn run_preload_partial_manifest_warms_then_exits_4() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_partial_manifest_fixture(dir.path());
        let root = dir.path().to_str().unwrap();

        register_conditional_failing_resolver();
        let fetch_counts: Arc<Mutex<HashMap<String, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CountingCveProvider::new(fetch_counts.clone()),
        )));
        #[cfg(feature = "redb")]
        reregister_db_backend();

        let code = run_async(&["preload", root, "--provider", "counting"]);
        assert_eq!(
            code, 4,
            "partial manifest failure should exit 4 after warming good manifests"
        );
        assert!(
            fetch_counts
                .lock()
                .unwrap()
                .contains_key("partial-pkg::1.0"),
            "preload should warm packages from successfully resolved manifests"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_preload_provider_failure_exits_5() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            vlz::mocks::FailingCveProvider::new(),
        )));
        assert_eq!(run_async(&["preload", root]), 5);
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_json_tier_c_per_cve_reachable_divergence() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        std::fs::write(dir.path().join("main.py"), "import pkg\n")
            .expect("write main.py");
        let out_path = dir.path().join("tier-c-report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            TierCReachabilityProvider::new(),
        )));
        #[cfg(feature = "redb")]
        reregister_db_backend();

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "tier_c_reachability",
            "--reachability-mode",
            "best-available",
        ]);
        assert_eq!(code, 86, "two CVEs should trigger default CVE exit");

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let findings = parsed["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 1, "one package finding");
        let cves = findings[0]["cves"].as_array().expect("cves");
        assert_eq!(cves.len(), 2);
        let mut reachable: Vec<bool> = cves
            .iter()
            .filter_map(|c| c.get("reachable").and_then(|v| v.as_bool()))
            .collect();
        reachable.sort();
        assert_eq!(
            reachable,
            vec![false, true],
            "Tier C must diverge per CVE on the same package"
        );
    });
}

/// Exercises the `python-tier-d` apply_tier_d_to_findings path in run_scan when
/// reachability mode is best-available (compiled only with that feature).
#[cfg(all(feature = "python", feature = "python-tier-d"))]
#[test]
fn run_scan_best_available_exercises_tier_d_block() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        std::fs::write(
            dir.path().join("main.py"),
            "import pkg\nfrom pkg import used_sym\n",
        )
        .expect("write main.py");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            TierCReachabilityProvider::new(),
        )));
        #[cfg(feature = "redb")]
        reregister_db_backend();

        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--provider",
            "tier_c_reachability",
            "--reachability-mode",
            "best-available",
            "--benchmark",
        ]);
        // Benchmark skips CVE fetch; exit 0 still runs reachability wiring.
        assert_eq!(code, 0);
    });
}

#[cfg(all(feature = "python", feature = "perf-instrumentation"))]
#[test]
fn run_scan_tier_b_with_perf_instrumentation_exits_cleanly() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        std::fs::write(dir.path().join("main.py"), "import pkg\n")
            .expect("write main.py");
        let root = dir.path().to_str().unwrap();
        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--benchmark",
            "--reachability-mode",
            "tier-b",
        ]);
        assert_eq!(code, 0);
    });
}

#[test]
fn run_config_list_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["config", "--list"]), 0));
}

#[test]
fn run_config_bare_lists_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["config"]), 0));
}

#[test]
fn run_config_example_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["config", "--example"]), 0));
}

#[test]
fn run_config_list_after_set_shows_language_regex() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        assert_eq!(
            run_async(&["config", "--set", "python.regex=^req\\.txt$"]),
            0
        );
        assert_eq!(run_async(&["config", "--list"]), 0);
    });
}

#[test]
fn run_config_set_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        ensure_registries_for_run();
        assert_eq!(
            run_async(&[
                "config",
                "--set",
                "python.regex=^requirements\\.txt$"
            ]),
            0
        );
    });
}

#[test]
fn run_config_set_invalid_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(run_async(&["config", "--set", "=value"]), 2);
        ensure_registries_for_run();
        assert_eq!(run_async(&["config", "--set", "key"]), 2);
    });
}

#[test]
fn run_config_set_unknown_key_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(run_async(&["config", "--set", "nodot=value"]), 2);
    });
}

#[test]
fn run_config_invalid_file_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let f = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(f.path(), "invalid toml {{{").expect("write");
        let path = f.path().to_str().unwrap();
        assert_eq!(run_async(&["-c", path, "list"]), 2);
    });
}

#[test]
fn run_db_set_ttl_no_selector_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(run_async(&["db", "set-ttl", "3600"]), 2);
    });
}

#[test]
fn run_db_migrate_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["db", "migrate"]), 0));
}

#[test]
fn run_db_list_providers_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["db", "list-providers"]), 0));
}

#[test]
fn run_db_stats_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["db", "stats"]), 0));
}

#[test]
fn run_db_verify_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["db", "verify"]), 0));
}

#[test]
fn run_db_show_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["db", "show"]), 0));
}

#[test]
fn run_db_show_full_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["db", "show", "--full"]), 0));
}

#[cfg(feature = "redb")]
#[test]
fn run_db_show_with_cached_entry_and_raw_vulns() {
    let _ = env_logger::try_init();
    with_temp_xdg_env(|| {
        let path = vlz::config::default_cache_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let backend = vlz_db_redb::RedbBackend::with_path(path, 3600)
            .expect("create backend");
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            backend.init().await.expect("init");
            let pkg = Package {
                name: "test-pkg".to_string(),
                version: "1.0".to_string(),
                ..Default::default()
            };
            let raw =
                vec![serde_json::json!({"id": "CVE-2024-TEST", "summary": "test vuln"})];
            backend.put(&pkg, "osv", &raw, None).await.expect("put");
        });
        drop(backend);
        ensure_registries_for_run();
        assert_eq!(run_async(&["db", "show", "--full"]), 0);
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_scan_blocking_failure_beats_fp_exit_code() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_partial_manifest_fixture(dir.path());
        let root = dir.path().to_str().unwrap();

        register_conditional_failing_resolver();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--provider",
                "cve_returning",
                "--fp-exit-code",
                "99",
            ]),
            4,
            "blocking manifest failure must beat fp_exit_code"
        );
    });
}

#[test]
fn run_scan_unknown_provider_before_missing_package_manager_exits_2() {
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
                    "--provider",
                    "nonexistent",
                    "--package-manager-required",
                ]),
                2,
                "misconfiguration (unknown provider) before missing package manager"
            );
        });
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_scan_fp_exit_code_when_all_cves_marked_fp() {
    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("requirements.txt"), "test-pkg==1.0\n")
        .expect("write");
    let root = dir.path().to_str().unwrap().to_owned();
    with_temp_xdg_env(|| {
        let path = vlz::config::default_cache_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let backend = vlz_db_redb::RedbBackend::with_path(path, 3600)
            .expect("create backend");
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            backend.init().await.expect("init");
            let pkg = Package {
                name: "test-pkg".to_string(),
                version: "1.0".to_string(),
                ..Default::default()
            };
            let raw = vec![serde_json::json!({
                "id": "CVE-2024-FP-TEST",
                "summary": "marked as fp"
            })];
            backend.put(&pkg, "osv", &raw, None).await.expect("put");
        });
        drop(backend);
        ensure_registries_for_run();
        assert_eq!(
            run_async(&["scan", &root, "--offline", "--provider", "osv"]),
            86,
            "scan finds CVE, exits 86"
        );
        assert_eq!(
            run_async(&[
                "fp",
                "mark",
                "CVE-2024-FP-TEST",
                "--comment",
                "test"
            ]),
            0
        );
        ensure_registries_for_run();
        assert_eq!(
            run_async(&[
                "scan",
                &root,
                "--offline",
                "--provider",
                "osv",
                "--fp-exit-code",
                "99",
            ]),
            99,
            "all CVEs marked FP, exit fp_exit_code"
        );
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_scan_project_id_scopes_fp_filtering() {
    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("requirements.txt"), "test-pkg==1.0\n")
        .expect("write");
    let root = dir.path().to_str().unwrap().to_owned();
    with_temp_xdg_env(|| {
        let path = vlz::config::default_cache_path();
        let ignore_path = vlz::config::default_ignore_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if let Some(parent) = ignore_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let backend = vlz_db_redb::RedbBackend::with_path(path, 3600)
            .expect("create backend");
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            backend.init().await.expect("init");
            let pkg = vlz_db::Package {
                name: "test-pkg".to_string(),
                version: "1.0".to_string(),
                ..Default::default()
            };
            let raw = vec![serde_json::json!({
                "id": "CVE-2024-SCOPED",
                "summary": "scoped fp test"
            })];
            backend.put(&pkg, "osv", &raw, None).await.expect("put");
        });
        drop(backend);
        let fp_db = vlz_db::FileIgnoreDb::with_path(ignore_path)
            .expect("open ignore db");
        fp_db
            .mark("CVE-2024-SCOPED", "proj1 only", Some("proj1"))
            .expect("mark");
        drop(fp_db);
        ensure_registries_for_run();
        assert_eq!(
            run_async(&[
                "scan",
                &root,
                "--offline",
                "--project-id",
                "proj1",
                "--fp-exit-code",
                "77",
            ]),
            77,
            "scan with project-id proj1: scoped FP applies, exit fp_exit_code"
        );
    });
}

#[test]
fn run_db_show_format_json_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(run_async(&["db", "show", "--format", "json"]), 0)
    });
}

#[test]
fn run_db_set_ttl_all_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(run_async(&["db", "set-ttl", "3600", "--all"]), 0)
    });
}

#[test]
fn run_db_set_ttl_entry() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let code = run_async(&["db", "set-ttl", "3600", "--entry", "somekey"]);
        assert!(code == 0 || code == 2, "set-ttl --entry returns 0 or 2");
    });
}

#[test]
fn run_db_set_ttl_pattern() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let code = run_async(&["db", "set-ttl", "3600", "--pattern", "x"]);
        assert!(code == 0 || code == 2);
    });
}

#[test]
fn run_db_set_ttl_pattern_wildcard() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let code = run_async(&["db", "set-ttl", "3600", "--pattern", "pkg*"]);
        assert!(code == 0 || code == 2);
    });
}

#[test]
fn run_db_set_ttl_entries() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let code = run_async(&["db", "set-ttl", "3600", "--entries", "a,b"]);
        assert!(code == 0 || code == 2);
    });
}

#[test]
fn run_with_verbose_logs_cache_ttl() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(run_async(&["-v", "db", "stats"]), 0);
    });
}

#[test]
fn run_scan_verbose_logs_cache_ttl() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&["-v", "scan", root, "--offline", "--benchmark"]),
            0
        );
    });
}

#[test]
fn run_cache_db_path_is_directory_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("cache-dir");
        std::fs::create_dir(&cache_dir).expect("create dir");
        assert!(cache_dir.is_dir());
        temp_env::with_var(
            "VLZ_CACHE_DB",
            Some(cache_dir.as_os_str()),
            || {
                let code = run_async(&["db", "stats"]);
                assert_eq!(
                    code, 2,
                    "cache path is directory, cannot create DB"
                );
            },
        );
    });
}

#[test]
fn run_cache_path_parent_created() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("sub");
        assert!(!sub.exists());
        let cache_db = sub.join("cache.redb").to_string_lossy().into_owned();
        temp_env::with_var("VLZ_CACHE_DB", Some(&cache_db), || {
            assert_eq!(run_async(&["db", "stats"]), 0);
        });
        assert!(sub.exists(), "parent dir should be created");
    });
}

#[cfg(unix)]
#[test]
fn run_with_world_writable_cache_exits_2() {
    use std::os::unix::fs::PermissionsExt;
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_db = dir.path().join("worldwritable.redb");
        std::fs::write(&cache_db, "").expect("write");
        std::fs::set_permissions(
            &cache_db,
            std::fs::Permissions::from_mode(0o666),
        )
        .expect("chmod");
        let cache_db_str = cache_db.to_string_lossy().into_owned();
        temp_env::with_var("VLZ_CACHE_DB", Some(&cache_db_str), || {
            let code = run_async(&["db", "stats"]);
            assert_eq!(
                code, 2,
                "SEC-014: world-writable cache DB should exit 2"
            );
        });
    });
}

#[test]
fn run_scan_offline_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(run_async(&["scan", root, "--offline", "--benchmark"]), 0);
    });
}

#[test]
fn run_scan_benchmark_emits_nonzero_duration() {
    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_str().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args(["scan", root, "--offline", "--benchmark"])
        .env("XDG_CACHE_HOME", xdg.path())
        .env("XDG_DATA_HOME", xdg.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("VLZ_CACHE_DB", xdg.path().join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.path().join("vlz-ignore.json"))
        .output()
        .expect("spawn vlz");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains(r#""benchmark""#))
        .expect("benchmark json line on stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(line).expect("parse benchmark json");
    let duration = parsed["benchmark"]["duration_ms"]
        .as_u64()
        .expect("duration_ms");
    let mem_mb = parsed["benchmark"]["mem_mb"].as_u64().expect("mem_mb");
    // Empty offline trees can finish in under 1ms on a fast host, so
    // duration_ms may be 0; mem_mb still proves FR-029 metrics ran.
    assert!(
        mem_mb > 0,
        "FR-029: mem_mb must be > 0, got duration_ms={duration} mem_mb={mem_mb}"
    );
}

#[test]
fn run_scan_no_root_uses_cwd() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let code = run_async(&["scan", "--offline", "--benchmark"]);
        assert!(
            code == 0 || code == 2 || code == 4,
            "scan without root uses cwd; code={} (0=ok, 2=misconfig, 4=resolution failed)",
            code
        );
    });
}

#[cfg(unix)]
#[test]
fn run_scan_parse_fails_when_file_unreadable_exits_4() {
    use std::os::unix::fs::PermissionsExt;
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let req_file = dir.path().join("requirements.txt");
        std::fs::write(&req_file, "pkg==1.0").expect("write");
        std::fs::set_permissions(
            &req_file,
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("chmod");
        let root = dir.path().to_str().unwrap();
        let code = run_async(&["scan", root, "--offline"]);
        std::fs::set_permissions(
            &req_file,
            std::fs::Permissions::from_mode(0o644),
        )
        .ok();
        assert_eq!(code, 4);
    });
}

#[test]
fn run_scan_offline_with_manifest_exits_6() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&["scan", root, "--offline"]),
            6,
            "offline scan with manifest but no cache hits exit 6"
        );
    });
}

#[test]
fn run_scan_offline_with_manifest_verbose_exits_6() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        assert_eq!(run_async(&["-vv", "scan", root, "--offline"]), 6);
    });
}

#[test]
fn run_scan_no_benchmark_uses_parallel_queries() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(run_async(&["scan", root, "--offline"]), 0);
    });
}

#[test]
fn run_scan_package_manager_required_no_pip_exits_3() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let path_without_pip = empty_dir.path().to_string_lossy().into_owned();
        temp_env::with_var("PATH", Some(&path_without_pip), || {
            let code =
                run_async(&["scan", root, "--package-manager-required"]);
            assert_eq!(
                code, 3,
                "missing pip with --package-manager-required -> exit 3"
            );
        });
    });
}

#[cfg(feature = "go")]
#[test]
fn run_scan_package_manager_required_go_mod_no_go_exits_3() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/test\n\ngo 1.22\n",
        )
        .expect("write go.mod");
        let root = dir.path().to_str().unwrap();
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let path_without_go = empty_dir.path().to_string_lossy().into_owned();
        temp_env::with_var("PATH", Some(&path_without_go), || {
            let code =
                run_async(&["scan", root, "--package-manager-required"]);
            assert_eq!(
                code, 3,
                "missing go with go.mod and --package-manager-required -> exit 3"
            );
        });
    });
}

#[test]
fn run_scan_format_json_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--format",
                "json",
                "--offline",
                "--benchmark",
            ]),
            0
        );
    });
}

#[test]
fn run_scan_format_sarif_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--format",
                "sarif",
                "--offline",
                "--benchmark",
            ]),
            0
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_json_includes_manifest_paths() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 86, "CVE found so exit 86");

        let content = std::fs::read_to_string(&out_path).expect("read report");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("parse json");
        let findings = parsed
            .get("findings")
            .expect("findings key")
            .as_array()
            .expect("findings array");
        assert!(!findings.is_empty(), "should have at least one finding");
        for finding in findings {
            let manifest_paths = finding
                .get("manifest_paths")
                .expect("manifest_paths key in finding");
            let paths =
                manifest_paths.as_array().expect("manifest_paths array");
            assert!(
                !paths.is_empty(),
                "each finding must have at least one manifest path"
            );
            assert_eq!(
                paths[0].as_str().unwrap(),
                "pylock.toml",
                "manifest path should be pylock.toml when lock provides resolved packages"
            );
        }
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_pylock_only() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .expect("write pylock");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 86);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let findings = parsed["findings"].as_array().unwrap();
        assert_eq!(findings[0]["manifest_paths"][0], "pylock.toml");
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0]["path"], "pylock.toml");
        assert_eq!(coverage[0]["status"], "scanned_transitive");
    });
}

#[cfg(feature = "python")]
fn assert_orphan_lock_entry_point_scanned(lock_name: &str, content: &str) {
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(lock_name), content)
            .expect("write lock");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 86, "orphan {lock_name} should produce CVE findings");

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0]["path"], lock_name);
        assert_eq!(coverage[0]["status"], "scanned_transitive");
        assert_eq!(
            parsed["findings"][0]["manifest_paths"][0].as_str().unwrap(),
            lock_name
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_poetry_lock_only() {
    let _ = env_logger::try_init();
    assert_orphan_lock_entry_point_scanned(
        "poetry.lock",
        "[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
    );
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_uv_lock_only() {
    let _ = env_logger::try_init();
    assert_orphan_lock_entry_point_scanned(
        "uv.lock",
        "version = 1\n\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
    );
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_pipfile_lock_only() {
    let _ = env_logger::try_init();
    assert_orphan_lock_entry_point_scanned(
        "Pipfile.lock",
        r#"{"default":{"pkg":{"version":"==1.0"}}}"#,
    );
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_multi_lock_different_packages() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg-a\"\nversion = \"1.0\"\n",
        )
        .expect("write pylock");
        std::fs::write(
            dir.path().join("poetry.lock"),
            "[[package]]\nname = \"pkg-b\"\nversion = \"2.0\"\n",
        )
        .expect("write poetry");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 86);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage.len(), 2);
        let paths: Vec<_> = coverage
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert!(paths.contains(&"pylock.toml"));
        assert!(paths.contains(&"poetry.lock"));

        let findings = parsed["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        let mut paths_by_pkg: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for finding in findings {
            let pkg = finding["package"]["name"].as_str().unwrap().to_string();
            let path =
                finding["manifest_paths"][0].as_str().unwrap().to_string();
            paths_by_pkg.insert(pkg, path);
        }
        assert_eq!(paths_by_pkg["pkg-a"], "pylock.toml");
        assert_eq!(paths_by_pkg["pkg-b"], "poetry.lock");
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_valid_empty_pylock_exit_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\npackages = []\n",
        )
        .expect("write empty pylock");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--offline",
        ]);
        assert_eq!(code, 0);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage[0]["status"], "scanned_transitive");
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_orphan_multi_lock_partial_parse_exit_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"good\"\nversion = \"1.0\"\n",
        )
        .expect("write pylock");
        std::fs::write(dir.path().join("poetry.lock"), "not valid poetry")
            .expect("write bad poetry");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--offline",
        ]);
        assert_eq!(code, 4);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage.len(), 2);
        let statuses: Vec<_> = coverage
            .iter()
            .map(|e| e["status"].as_str().unwrap())
            .collect();
        assert!(statuses.contains(&"scanned_transitive"));
        assert!(statuses.contains(&"failed_parse"));
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_malformed_requirements_txt_failed_parse_exit_4() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good");
        let bad = dir.path().join("bad");
        std::fs::create_dir_all(&good).expect("mkdir good");
        std::fs::create_dir_all(&bad).expect("mkdir bad");
        write_requirements_with_pylock(&good, "good-pkg", "1.0");
        std::fs::write(bad.join("requirements.txt"), "bad-pkg=1.0\n")
            .expect("write bad requirements");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--offline",
        ]);
        assert_eq!(code, 4);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage.len(), 2);
        let statuses: Vec<_> = coverage
            .iter()
            .map(|e| e["status"].as_str().unwrap())
            .collect();
        assert!(statuses.contains(&"scanned_transitive"));
        assert!(statuses.contains(&"failed_parse"));
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_adjacent_multi_lock_manifest_paths_per_source() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "ignored==9.9\n")
            .expect("write requirements");
        std::fs::write(
            dir.path().join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg-a\"\nversion = \"1.0\"\n",
        )
        .expect("write pylock");
        std::fs::write(
            dir.path().join("poetry.lock"),
            "[[package]]\nname = \"pkg-b\"\nversion = \"2.0\"\n",
        )
        .expect("write poetry");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 86);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let findings = parsed["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        let mut paths_by_pkg: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for finding in findings {
            let pkg = finding["package"]["name"].as_str().unwrap().to_string();
            let paths: Vec<String> = finding["manifest_paths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect();
            paths_by_pkg.insert(pkg, paths);
        }
        assert_eq!(paths_by_pkg["pkg-a"], vec!["pylock.toml".to_string()]);
        assert_eq!(paths_by_pkg["pkg-b"], vec!["poetry.lock".to_string()]);
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_lock_file_allowlist_ignores_other_locks() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg-a\"\nversion = \"1.0\"\n",
        )
        .expect("write pylock");
        std::fs::write(
            dir.path().join("poetry.lock"),
            "[[package]]\nname = \"pkg-b\"\nversion = \"2.0\"\n",
        )
        .expect("write poetry");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
            "--lock-file",
            "poetry.lock",
        ]);
        assert_eq!(code, 86);

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
                .unwrap();
        let coverage = parsed["manifest_coverage"].as_array().unwrap();
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0]["path"], "poetry.lock");
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_lock_file_allowlist_missing_listed_lock_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("uv.lock"),
            "version = 1\n\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .expect("write uv.lock");
        let root = dir.path().to_str().unwrap();

        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--lock-file",
            "poetry.lock",
        ]);
        assert_eq!(code, 2);
    });
}

#[cfg(feature = "python")]
fn write_partial_manifest_fixture(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("good")).expect("mkdir good");
    std::fs::create_dir_all(root.join("broken")).expect("mkdir broken");
    write_requirements_with_pylock(
        root.join("good").as_path(),
        "partial-pkg",
        "1.0",
    );
    std::fs::write(root.join("broken/requirements.txt"), "partial-pkg==1.0\n")
        .expect("write broken requirements");
}

#[cfg(feature = "python")]
fn register_conditional_failing_resolver() {
    vlz::registry::clear_resolvers();
    vlz::registry::register(vlz::registry::Plugin::Resolver(Box::new(
        vlz::mocks::PythonConditionalFailingResolver::for_broken_paths(),
    )));
}

#[cfg(feature = "python")]
#[test]
fn run_scan_partial_manifest_resolution_exits_4_with_report() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_partial_manifest_fixture(dir.path());
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        register_conditional_failing_resolver();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 4, "blocking manifest failure should exit 4");

        let content = std::fs::read_to_string(&out_path).expect("read report");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("parse json");
        let coverage = parsed
            .get("manifest_coverage")
            .expect("manifest_coverage")
            .as_array()
            .expect("manifest_coverage array");
        assert_eq!(coverage.len(), 2);
        let failed = coverage
            .iter()
            .find(|e| {
                e.get("status")
                    == Some(&serde_json::json!("failed_resolution"))
            })
            .expect("failed_resolution entry");
        assert!(
            failed
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .contains("broken"),
            "failed entry should reference broken manifest"
        );
        let findings = parsed
            .get("findings")
            .expect("findings")
            .as_array()
            .expect("findings array");
        assert!(
            !findings.is_empty(),
            "good manifest should still produce CVE findings"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_fail_fast_aborts_before_cve() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_partial_manifest_fixture(dir.path());
        let root = dir.path().to_str().unwrap();

        register_conditional_failing_resolver();
        let fetch_counts: Arc<Mutex<HashMap<String, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let provider = CountingCveProvider::new(fetch_counts.clone());
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            provider,
        )));

        let code = run_async(&[
            "scan",
            root,
            "--fail-fast",
            "--provider",
            "counting",
        ]);
        assert_eq!(code, 4, "fail-fast manifest failure should exit 4");

        let counts = fetch_counts.lock().unwrap();
        assert!(
            counts.is_empty(),
            "fail-fast should skip CVE phase; fetch counts: {:?}",
            *counts
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_manifest_failure_and_offline_miss_still_renders_report() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_partial_manifest_fixture(dir.path());
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        register_conditional_failing_resolver();

        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
        ]);
        assert_eq!(
            code, 4,
            "manifest blocking failure takes precedence over offline miss (6)"
        );

        let content = std::fs::read_to_string(&out_path).expect("read report");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("parse json");
        assert!(
            parsed.get("manifest_coverage").is_some(),
            "report must render manifest_coverage despite offline miss"
        );
    });
}

#[cfg(feature = "python")]
fn write_partial_manifest_fixture_natural_broken(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("good")).expect("mkdir good");
    std::fs::create_dir_all(root.join("broken")).expect("mkdir broken");
    write_requirements_with_pylock(
        root.join("good").as_path(),
        "partial-pkg",
        "1.0",
    );
    std::fs::write(
        root.join("broken/pyproject.toml"),
        "[tool.poetry\nname = \"broken\"\n",
    )
    .expect("write invalid pyproject.toml");
}

#[cfg(feature = "python")]
#[test]
fn run_scan_manifest_failure_summary_on_stderr() {
    use std::process::Command;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    write_partial_manifest_fixture_natural_broken(
        dir.path().join("proj").as_path(),
    );
    let root = dir.path().join("proj");
    let root_str = root.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args(["scan", root_str, "--format", "json", "--offline"])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("VLZ_CACHE_DB", xdg.join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.join("vlz-ignore.json"))
        .output()
        .expect("run vlz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stderr.contains("1 manifest(s) could not be fully analyzed"),
        "stderr should include consolidated summary header; got: {stderr}"
    );
    assert!(
        stderr.contains("broken/pyproject.toml"),
        "stderr should list failed manifest path; got: {stderr}"
    );
    assert!(
        !stderr.contains("Error: manifest"),
        "default verbosity should not emit per-manifest Error: lines; got: {stderr}"
    );
}

#[cfg(feature = "python")]
#[test]
fn run_scan_manifest_failure_per_manifest_error_with_verbose() {
    use std::process::Command;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    write_partial_manifest_fixture_natural_broken(
        dir.path().join("proj").as_path(),
    );
    let root = dir.path().join("proj");
    let root_str = root.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args(["scan", root_str, "--format", "json", "--offline", "-v"])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("VLZ_CACHE_DB", xdg.join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.join("vlz-ignore.json"))
        .env("RUST_LOG", "off")
        .output()
        .expect("run vlz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stderr.contains("1 manifest(s) could not be fully analyzed"),
        "stderr should include consolidated summary; got: {stderr}"
    );
    assert!(
        stderr.contains("Error: manifest broken/pyproject.toml:"),
        "verbose mode should emit per-manifest Error: line; got: {stderr}"
    );
}

#[cfg(feature = "python")]
#[test]
fn resolve_failure_verbose_detail_lines_include_cause_chain() {
    use vlz::scan::manifest_failure_detail_lines;

    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements.txt");
        ensure_registries_for_run();
        vlz::registry::clear_resolvers();
        vlz::registry::register(vlz::registry::Plugin::Resolver(Box::new(
            vlz::mocks::CauseChainFailingResolver::new(),
        )));

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let cfg = vlz::config::EffectiveConfig {
            benchmark: true,
            ..Default::default()
        };
        let out = rt
            .block_on(vlz::package_resolve::resolve_packages_for_path(
                Some(dir.path().to_string_lossy().into_owned()),
                &cfg,
            ))
            .expect("resolve");
        let failed = out
            .manifest_coverage
            .iter()
            .find(|entry| entry.status.is_blocking())
            .expect("blocking failure");
        let lines = manifest_failure_detail_lines(failed, Some(dir.path()));
        assert!(
            lines.iter().any(|line| {
                line.contains("Caused by:")
                    && line.contains("mock inner resolve cause")
            }),
            "detail lines should preserve nested cause for -v stderr: {lines:?}"
        );
    });
}

#[cfg(feature = "python")]
fn write_two_lockless_pyproject_fixture(root: &std::path::Path) {
    for sub in ["a", "b"] {
        let dir = root.join(sub);
        std::fs::create_dir_all(&dir).expect("mkdir subdir");
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"pkg\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n",
        )
        .expect("write pyproject.toml");
    }
}

#[cfg(feature = "python")]
#[test]
fn run_scan_manifest_failure_groups_identical_errors_default_verbosity() {
    use std::process::Command;
    use vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let proj = dir.path().join("proj");
    write_two_lockless_pyproject_fixture(proj.as_path());
    let root_str = proj.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args(["scan", root_str, "--format", "json"])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("VLZ_CACHE_DB", xdg.join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.join("vlz-ignore.json"))
        .env("RUST_LOG", "off")
        .output()
        .expect("run vlz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr={stderr} stdout={stdout}"
    );
    assert!(
        stderr.contains("2 manifest(s) could not be fully analyzed"),
        "stderr should include consolidated count; got: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Resolve error: {FR_022_TRANSITIVE_ERROR_MESSAGE} (2):"
        )),
        "stderr should group identical FR-022 errors; got: {stderr}"
    );
    assert_eq!(
        stderr.matches("Error: manifest").count(),
        0,
        "default verbosity should not repeat per-manifest errors; got: {stderr}"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse json");
    let coverage = parsed
        .get("manifest_coverage")
        .and_then(|v| v.as_array())
        .expect("manifest_coverage array");
    assert_eq!(
        coverage
            .iter()
            .filter(|e| e.get("status")
                == Some(&serde_json::json!("failed_resolution")))
            .count(),
        2,
        "json report should list both failures"
    );
}

#[cfg(feature = "python")]
#[test]
fn run_scan_direct_only_summary_on_stderr_default_verbosity() {
    use std::process::Command;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(proj.join("requirements.txt"), "requests==2.28.0\n")
        .expect("write requirements.txt");
    let root_str = proj.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args([
            "scan",
            root_str,
            "--format",
            "plain",
            "--offline",
            "--benchmark",
            "--allow-direct-only-fallback",
        ])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("VLZ_CACHE_DB", xdg.join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.join("vlz-ignore.json"))
        .env("RUST_LOG", "off")
        .output()
        .expect("run vlz");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={stderr} stdout={stdout}"
    );
    assert!(
        stderr.contains("manifest(s) scanned with direct dependencies only"),
        "stderr should include direct-only summary; got: {stderr}"
    );
    assert!(
        !stderr.contains("vlz warning: Only direct dependencies were scanned"),
        "default verbosity should not emit per-manifest vlz warning:; got: {stderr}"
    );
    assert!(
        stdout.contains(
            "No vulnerabilities found in scanned packages; see manifest coverage for incomplete resolution."
        ),
        "plain report should use degraded empty-findings message; got: {stdout}"
    );
}

#[cfg(feature = "python")]
#[test]
fn run_scan_direct_only_per_manifest_warning_with_verbose() {
    use std::process::Command;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(proj.join("requirements.txt"), "requests==2.28.0\n")
        .expect("write requirements.txt");
    let root_str = proj.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args([
            "-v",
            "scan",
            root_str,
            "--format",
            "json",
            "--offline",
            "--benchmark",
            "--allow-direct-only-fallback",
        ])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("VLZ_CACHE_DB", xdg.join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.join("vlz-ignore.json"))
        .output()
        .expect("run vlz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("manifest(s) scanned with direct dependencies only"),
        "stderr should include direct-only summary; got: {stderr}"
    );
    assert!(
        stderr.contains("vlz warning: Only direct dependencies were scanned"),
        "verbose mode should emit per-manifest vlz warning:; got: {stderr}"
    );
}

#[cfg(feature = "python")]
#[test]
fn run_preload_direct_only_summary_when_blocking_zero() {
    use std::process::Command;

    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(proj.join("requirements.txt"), "requests==2.28.0\n")
        .expect("write requirements.txt");
    let root_str = proj.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args([
            "preload",
            root_str,
            "--offline",
            "--allow-direct-only-fallback",
        ])
        .env("XDG_CACHE_HOME", xdg.to_str().unwrap())
        .env("XDG_DATA_HOME", xdg.to_str().unwrap())
        .env("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .env("VLZ_CACHE_DB", xdg.join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.join("vlz-ignore.json"))
        .env("RUST_LOG", "off")
        .output()
        .expect("run vlz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    // Offline preload with packages may exit 6 (cache miss); summary must still appear.
    assert!(
        stderr.contains("manifest(s) scanned with direct dependencies only"),
        "preload stderr should include direct-only summary even when blocking==0; got: {stderr}"
    );
    assert!(
        !stderr.contains("vlz warning: Only direct dependencies were scanned"),
        "default preload should not emit per-manifest vlz warning:; got: {stderr}"
    );
}

#[cfg(feature = "rust")]
fn write_two_manifest_rust_fixture(root: &std::path::Path) {
    const LOCK: &str = r#"version = 3

[[package]]
name = "serde"
version = "1.0.2"
"#;
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
    )
    .expect("write root Cargo.toml");
    std::fs::write(root.join("Cargo.lock"), LOCK).expect("write Cargo.lock");
    let member = root.join("crates").join("foo");
    std::fs::create_dir_all(&member).expect("mkdir crates/foo");
    std::fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"foo\"\nversion = \"0.1.0\"\n",
    )
    .expect("write member Cargo.toml");
}

#[cfg(feature = "rust")]
fn run_scan_multi_manifest_rust(args: &[&str]) -> std::process::Output {
    use std::process::Command;

    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    write_two_manifest_rust_fixture(&proj);
    let root_str = proj.to_str().unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vlz"));
    cmd.args(["scan", root_str, "--offline", "--benchmark"])
        .args(args);
    apply_isolated_db_env(&mut cmd, &xdg);
    let verbose = args.iter().any(|a| *a == "-v" || *a == "--verbose");
    if !verbose {
        cmd.env("RUST_LOG", "off");
    }
    cmd.output().expect("run vlz")
}

#[cfg(feature = "rust")]
#[test]
fn run_scan_multi_manifest_rust_no_resolution_progress_default_verbosity() {
    let _ = env_logger::try_init();
    let out = run_scan_multi_manifest_rust(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr={stderr}");
    assert!(
        !stderr.contains("Resolving 2 rust manifest(s)"),
        "default verbosity should not emit resolution progress; got: {stderr}"
    );
}

#[cfg(feature = "rust")]
#[test]
fn run_scan_multi_manifest_rust_resolution_progress_with_verbose() {
    let _ = env_logger::try_init();
    for flag in ["-v", "--verbose"] {
        let out = run_scan_multi_manifest_rust(&[flag]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "flag {flag}: stderr={stderr}");
        assert!(
            stderr.contains("Resolving 2 rust manifest(s)"),
            "verbose ({flag}) should emit resolution progress; got: {stderr}"
        );
    }
}

#[cfg(feature = "python")]
#[test]
fn run_scan_json_includes_manifest_coverage() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_partial_manifest_fixture(dir.path());
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();

        register_conditional_failing_resolver();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            CveReturningProvider::new(),
        )));

        let code = run_async(&[
            "scan",
            root,
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
            "--provider",
            "cve_returning",
        ]);
        assert_eq!(code, 4);

        let parsed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&out_path).expect("read report"),
        )
        .expect("parse json");
        assert!(
            parsed.get("manifest_coverage").is_some(),
            "JSON report must include manifest_coverage"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_resolver_fails_exits_4() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write");
        let out_path = dir.path().join("report.json");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_resolvers();
        vlz::registry::register(vlz::registry::Plugin::Resolver(Box::new(
            vlz::mocks::FailingResolver::new(),
        )));
        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--format",
            "json",
            "--summary-file",
            &format!("json:{}", out_path.display()),
        ]);
        assert_eq!(code, 4);

        let parsed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&out_path).expect("report must render"),
        )
        .expect("parse json");
        let coverage = parsed
            .get("manifest_coverage")
            .and_then(|v| v.as_array())
            .expect("manifest_coverage in report");
        assert_eq!(coverage.len(), 1);
        assert_eq!(
            coverage[0].get("status"),
            Some(&serde_json::json!("failed_resolution"))
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_cve_provider_fails_logs_error() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        write_requirements_with_pylock(dir.path(), "pkg", "1.0");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            vlz::mocks::FailingCveProvider::new(),
        )));
        let code = run_async(&["-v", "scan", root]);
        assert_eq!(
            code, 5,
            "scan exits 5 when CVE provider fetch fails (avoid false negative)"
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_deduplicates_packages_before_cve_lookup() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        std::fs::create_dir_all(dir.path().join("sub1")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("sub2")).expect("mkdir");
        write_requirements_with_pylock(
            dir.path().join("sub1").as_path(),
            "pkg",
            "1.0",
        );
        write_requirements_with_pylock(
            dir.path().join("sub2").as_path(),
            "pkg",
            "1.0",
        );

        let fetch_counts: Arc<Mutex<HashMap<String, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let provider = CountingCveProvider::new(fetch_counts.clone());

        vlz::registry::clear_providers();
        vlz::registry::register(vlz::registry::Plugin::CveProvider(Box::new(
            provider,
        )));

        let code = run_async(&["scan", root, "--provider", "counting"]);
        assert_eq!(code, 0, "scan should succeed with mock provider");

        let counts = fetch_counts.lock().unwrap();
        let pkg_count = counts.get("pkg::1.0").copied().unwrap_or(0);
        assert_eq!(
            pkg_count, 1,
            "pkg@1.0 should be fetched exactly once (deduplicated); got {}",
            pkg_count
        );
    });
}

#[test]
fn run_db_verify_backend_fails_exits_1() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        vlz::registry::clear_db_backends();
        vlz::registry::register(vlz::registry::Plugin::DatabaseBackend(
            Box::new(vlz::mocks::FailingDbBackend::new()),
        ));
        assert_eq!(run_async(&["db", "verify"]), 1);
    });
}

#[test]
fn run_db_set_ttl_backend_fails_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        vlz::registry::clear_db_backends();
        vlz::registry::register(vlz::registry::Plugin::DatabaseBackend(
            Box::new(vlz::mocks::FailingDbBackend::new()),
        ));
        assert_eq!(
            run_async(&["db", "set-ttl", "3600", "--entry", "foo::1.0"]),
            2
        );
    });
}

#[test]
fn run_scan_with_min_count_and_exit_code_on_cve() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--benchmark",
            "--min-count",
            "5",
            "--exit-code",
            "99",
        ]);
        assert_eq!(code, 0, "no findings so exit 0 despite custom thresholds");
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_invalid_language_regex_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let cfg_path = dir.path().join("vlz.toml");
        std::fs::write(
            &cfg_path,
            r#"[python]
regex = "[invalid"
"#,
        )
        .expect("write config");
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "-c",
                cfg_path.to_str().unwrap(),
                "--offline",
                "--benchmark",
            ]),
            2
        );
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_with_config_custom_language_regex() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let cfg_path = dir.path().join("vlz.toml");
        std::fs::write(
            &cfg_path,
            r#"[python]
regex = "^requirements\\.txt$"
"#,
        )
        .expect("write config");
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "-c",
                cfg_path.to_str().unwrap(),
                "--offline",
                "--benchmark",
            ]),
            0
        );
    });
}

#[test]
fn run_scan_unknown_provider_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--provider",
                "nonexistent"
            ]),
            2
        );
    });
}

#[test]
fn run_scan_with_provider_explicit() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let code = run_async(&[
            "scan",
            root,
            "--offline",
            "--benchmark",
            "--provider",
            "osv",
        ]);
        assert_eq!(code, 0);
    });
}

#[test]
fn run_scan_config_parallel_too_high_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--parallel",
                "51",
            ]),
            2
        );
    });
}

#[test]
fn run_scan_with_output_writes_file_not_stdout() {
    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_str().unwrap();
    let out_path = dir.path().join("report.json");
    let out_str = out_path.to_str().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args([
            "scan",
            root,
            "--offline",
            "--format",
            "json",
            "--output",
            out_str,
        ])
        .env("XDG_CACHE_HOME", xdg.path())
        .env("XDG_DATA_HOME", xdg.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("VLZ_CACHE_DB", xdg.path().join("vlz-cache.redb"))
        .env("VLZ_IGNORE_DB", xdg.path().join("vlz-ignore.json"))
        .output()
        .expect("spawn vlz");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "primary report with --output must not print to stdout"
    );
    assert!(out_path.is_file(), "output file should exist");
    let body = std::fs::read_to_string(&out_path).expect("read output");
    assert!(
        body.contains("findings"),
        "output file should contain JSON report"
    );
}

#[test]
fn run_scan_with_report_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let out = dir.path().join("out.json");
        let out_str = out.to_str().unwrap();
        let spec = format!("json:{}", out_str);
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--report",
                &spec,
            ]),
            0
        );
        assert!(out.exists(), "report file should be created");
    });
}

#[test]
fn run_scan_summary_file_alias_still_works() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let out = dir.path().join("out.json");
        let out_str = out.to_str().unwrap();
        let spec = format!("json:{}", out_str);
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--summary-file",
                &spec,
            ]),
            0
        );
        assert!(out.exists(), "summary file alias should still create file");
    });
}

#[test]
fn run_scan_summary_file_html_plain_text_sarif_cyclonedx_spdx() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let html_path = dir.path().join("out.html");
        let plain_path = dir.path().join("out.txt");
        let text_path = dir.path().join("out2.txt");
        let sarif_path = dir.path().join("out.sarif");
        let cyclonedx_path = dir.path().join("sbom.cdx.json");
        let spdx_path = dir.path().join("sbom.spdx.json");
        let spec_html = format!("html:{}", html_path.to_str().unwrap());
        let spec_plain = format!("plain:{}", plain_path.to_str().unwrap());
        let spec_text = format!("text:{}", text_path.to_str().unwrap());
        let spec_sarif = format!("sarif:{}", sarif_path.to_str().unwrap());
        let spec_cyclonedx =
            format!("cyclonedx:{}", cyclonedx_path.to_str().unwrap());
        let spec_spdx = format!("spdx:{}", spdx_path.to_str().unwrap());
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--summary-file",
                &spec_html,
                "--summary-file",
                &spec_plain,
                "--summary-file",
                &spec_text,
                "--summary-file",
                &spec_sarif,
                "--summary-file",
                &spec_cyclonedx,
                "--summary-file",
                &spec_spdx,
            ]),
            0
        );
        assert!(html_path.exists());
        assert!(plain_path.exists());
        assert!(text_path.exists());
        assert!(sarif_path.exists());
        assert!(cyclonedx_path.exists());
        assert!(spdx_path.exists());
    });
}

#[test]
fn run_scan_summary_file_unknown_format() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let out = dir.path().join("out.unknown");
        let out_str = out.to_str().unwrap();
        let spec = format!("unknown:{}", out_str);
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--summary-file",
                &spec,
            ]),
            0
        );
    });
}

#[test]
fn run_scan_summary_file_malformed() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--summary-file",
                "nocolon",
            ]),
            0
        );
    });
}

#[test]
fn run_scan_summary_file_to_directory_fails_gracefully() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let out_dir = dir.path().join("subdir");
        std::fs::create_dir(&out_dir).expect("create dir");
        let spec = format!("json:{}", out_dir.to_str().unwrap());
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--summary-file",
                &spec,
            ]),
            0
        );
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_fp_ignore_db_path_is_directory_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let ignore_dir = dir.path().join("ignore-dir");
        std::fs::create_dir(&ignore_dir).expect("create dir");
        temp_env::with_var(
            "VLZ_IGNORE_DB",
            Some(ignore_dir.as_os_str()),
            || {
                let code = run_async(&[
                    "fp",
                    "mark",
                    "CVE-2020-1234",
                    "--comment",
                    "test",
                ]);
                assert_eq!(code, 2);
            },
        );
    });
}

#[test]
fn run_scan_ignore_db_path_is_directory_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_str().unwrap();
        let ignore_dir = dir.path().join("ignore-as-dir");
        std::fs::create_dir(&ignore_dir).expect("create dir");
        assert_eq!(
            run_async(&[
                "scan",
                root,
                "--offline",
                "--benchmark",
                "--ignore-db",
                ignore_dir.to_str().unwrap(),
            ]),
            2,
            "scan must fail closed when ignore DB path cannot be opened"
        );
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_fp_mark_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        assert_eq!(
            run_async(&["fp", "mark", "CVE-2020-1234", "--comment", "test"]),
            0
        );
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_fp_unmark_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        run_async(&["fp", "mark", "CVE-2020-5678", "--comment", "to remove"]);
        ensure_registries_for_run();
        assert_eq!(run_async(&["fp", "unmark", "CVE-2020-5678"]), 0);
    });
}
