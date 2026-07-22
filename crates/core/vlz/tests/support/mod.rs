// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared helpers for vlz integration tests (DOC-004 exit-code matrix, run_inprocess).

use clap::Parser;
use vlz::cli::Cli;

pub fn with_temp_xdg<F, R>(f: F) -> R
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

/// Write `requirements.txt` plus adjacent `pylock.toml` for transitive resolution in tests.
#[cfg(feature = "python")]
pub fn write_requirements_with_pylock(
    dir: &std::path::Path,
    pkg: &str,
    version: &str,
) {
    std::fs::write(
        dir.join("requirements.txt"),
        format!("{pkg}=={version}\n"),
    )
    .expect("write requirements.txt");
    std::fs::write(
        dir.join("pylock.toml"),
        format!(
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"{pkg}\"\nversion = \"{version}\"\n"
        ),
    )
    .expect("write pylock.toml");
}

pub fn ensure_registries_for_run() {
    let _guard = vlz::registry::registry_test_mutex()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    vlz::registry::ensure_default_manifest_finder();
    vlz::registry::ensure_default_parser();
    vlz::registry::ensure_default_resolver();
    let cfg = vlz::config::EffectiveConfig {
        provider_http_connect_timeout_secs:
            vlz::config::DEFAULT_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS,
        provider_http_request_timeout_secs:
            vlz::config::DEFAULT_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS,
        ..Default::default()
    };
    vlz::registry::ensure_default_cve_provider(&cfg);
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

pub fn run_async(args: &[&str]) -> i32 {
    let _guard = vlz::registry::registry_test_mutex()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut v = vec!["vlz"];
    v.extend(args.iter().copied());
    let args = match Cli::try_parse_from(v) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
        }
    };
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(vlz::run(args)).unwrap_or(2)
}
