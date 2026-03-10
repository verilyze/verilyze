// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::Parser;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vlz::cli::Cli;
use vlz::mocks::CountingCveProvider;
use vlz_db::{DatabaseBackend, Package};

fn with_temp_xdg<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().to_string_lossy().into_owned();
    temp_env::with_var("XDG_CACHE_HOME", Some(p.as_str()), || {
        temp_env::with_var("XDG_DATA_HOME", Some(p.as_str()), || {
            temp_env::with_var("XDG_CONFIG_HOME", Some(p.as_str()), || {
                ensure_registries_for_run();
                f()
            })
        })
    })
}

fn ensure_registries_for_run() {
    let _guard = vlz::registry::registry_test_mutex().lock().unwrap();
    vlz::registry::ensure_default_manifest_finder();
    vlz::registry::ensure_default_parser();
    vlz::registry::ensure_default_resolver();
    vlz::registry::ensure_default_cve_provider();
    vlz::registry::ensure_default_reporter();
    vlz::registry::ensure_default_integrity_checker();
    #[cfg(feature = "redb")]
    {
        let cache_path = vlz::config::default_cache_path();
        let _ = vlz::registry::ensure_default_db_backend_with_path(
            cache_path,
            vlz::config::DEFAULT_CACHE_TTL_SECS,
        );
    }
}

fn run_async(args: &[&str]) -> i32 {
    let _guard = vlz::registry::registry_test_mutex().lock().unwrap();
    let mut v = vec!["vlz"];
    v.extend(args.iter().copied());
    let args = Cli::parse_from(v);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(vlz::run(args)).unwrap_or(2)
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
fn run_list_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["list"]), 0));
}

#[test]
fn run_preload_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["preload"]), 0));
}

#[test]
fn run_config_list_exits_0() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| assert_eq!(run_async(&["config", "--list"]), 0));
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
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().to_string_lossy().into_owned();
    temp_env::with_var("XDG_CACHE_HOME", Some(p.as_str()), || {
        temp_env::with_var("XDG_DATA_HOME", Some(p.as_str()), || {
            temp_env::with_var("XDG_CONFIG_HOME", Some(p.as_str()), || {
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
            })
        })
    });
}

#[cfg(feature = "redb")]
#[test]
fn run_scan_fp_exit_code_when_all_cves_marked_fp() {
    let _ = env_logger::try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("requirements.txt"), "test-pkg==1.0\n")
        .expect("write");
    let root = dir.path().to_str().unwrap();
    let p = dir.path().to_string_lossy().into_owned();
    temp_env::with_var("XDG_CACHE_HOME", Some(p.as_str()), || {
        temp_env::with_var("XDG_DATA_HOME", Some(p.as_str()), || {
            temp_env::with_var("XDG_CONFIG_HOME", Some(p.as_str()), || {
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
                    run_async(&["scan", root, "--offline"]),
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
                assert_eq!(
                    run_async(&[
                        "scan",
                        root,
                        "--offline",
                        "--fp-exit-code",
                        "99",
                    ]),
                    99,
                    "all CVEs marked FP, exit fp_exit_code"
                );
            })
        })
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
fn run_scan_no_root_uses_cwd() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let code = run_async(&["scan", "--offline", "--benchmark"]);
        assert!(
            code == 0 || code == 2 || code == 4,
            "scan without root uses cwd; code={} (0=ok, 2=error, 4=offline with manifests)",
            code
        );
    });
}

#[cfg(unix)]
#[test]
fn run_scan_parse_fails_when_file_unreadable_exits_2() {
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
        assert_eq!(code, 2);
    });
}

#[test]
fn run_scan_offline_with_manifest_exits_4() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        assert_eq!(
            run_async(&["scan", root, "--offline"]),
            4,
            "offline scan with manifest but no cache hits exit 4"
        );
    });
}

#[test]
fn run_scan_offline_with_manifest_verbose_exits_4() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write requirements");
        let root = dir.path().to_str().unwrap();
        assert_eq!(run_async(&["-vv", "scan", root, "--offline"]), 4);
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
        let root = dir.path().to_str().unwrap();
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let path_without_pip = empty_dir.path().to_string_lossy().into_owned();
        temp_env::with_var("PATH", Some(&path_without_pip), || {
            let code = run_async(&[
                "scan",
                root,
                "--offline",
                "--package-manager-required",
            ]);
            assert_eq!(
                code, 3,
                "missing pip with --package-manager-required -> exit 3"
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
fn run_scan_resolver_fails_exits_2() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write");
        let root = dir.path().to_str().unwrap();
        vlz::registry::clear_resolvers();
        vlz::registry::register(vlz::registry::Plugin::Resolver(Box::new(
            vlz::mocks::FailingResolver::new(),
        )));
        assert_eq!(run_async(&["scan", root, "--offline"]), 2);
    });
}

#[cfg(feature = "python")]
#[test]
fn run_scan_cve_provider_fails_logs_error() {
    let _ = env_logger::try_init();
    with_temp_xdg(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
            .expect("write");
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
        std::fs::write(dir.path().join("sub1/requirements.txt"), "pkg==1.0\n")
            .expect("write");
        std::fs::write(dir.path().join("sub2/requirements.txt"), "pkg==1.0\n")
            .expect("write");

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
            "--exit-code-on-cve",
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
fn run_scan_with_summary_file_exits_0() {
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
        assert!(out.exists(), "summary file should be created");
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
