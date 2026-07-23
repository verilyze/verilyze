// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use clap::Parser;

pub mod cache_warm;
pub mod cli;
pub mod cli_values;
#[cfg(feature = "completions")]
pub mod completion;
pub mod config;
pub mod config_example;
pub mod exit_code;
pub mod package_resolve;
pub mod registry;
pub mod run;
pub mod scan;

mod benchmark_metrics;

pub use benchmark_metrics::BENCHMARK_MAX_MS;

#[cfg(any(test, feature = "testing"))]
pub mod mocks;

pub use run::run;

/// Map a top-level task join result to a process exit code (panic -> 1).
pub fn exit_code_from_join_result(
    join_result: Result<i32, tokio::task::JoinError>,
) -> i32 {
    match join_result {
        Ok(code) => code,
        Err(join_err) => {
            if let Ok(panic) = join_err.try_into_panic() {
                log::error!("internal error: {}", panic_message(&panic));
            }
            exit_code::EXIT_INTERNAL_ERROR
        }
    }
}

/// Extract a display string from a panic payload.
pub fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> &str {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "unknown panic"
    }
}

/// Entry point logic: init logger, parse CLI, run command, return exit code.
/// Used by the binary.
pub async fn run_main() -> i32 {
    run_main_from_args(std::env::args()).await
}

/// Same as [`run_main`] but accepts args. Used by the binary and by tests.
pub async fn run_main_from_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone + AsRef<std::ffi::OsStr>,
{
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "warn")
        .write_style_or("RUST_LOG_STYLE", "always");
    let args_vec: Vec<_> = args.into_iter().collect();
    let verbose_count = args_vec
        .iter()
        .filter(|a| {
            Into::<std::ffi::OsString>::into((*a).clone()).to_string_lossy()
                == "-v"
        })
        .count();
    let log_filter = run::log_level_from_verbosity_count(verbose_count);
    // env_logger::init() may only succeed once per process; allow re-entry from
    // tests that call run_main_from_args more than once.
    let _ = env_logger::Builder::from_env(env)
        .filter_level(log_filter)
        .try_init();

    let args = match cli::Cli::try_parse_from(args_vec) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            // OP-012: --help and --version are informational; exit 0.
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion => {
                    exit_code::EXIT_SUCCESS
                }
                _ => exit_code::EXIT_MISCONFIGURATION,
            };
            return code;
        }
    };
    let verbose = args.verbose;
    run(args).await.unwrap_or_else(|e| {
        if run::is_broken_pipe(&e) {
            exit_code::EXIT_SUCCESS
        } else {
            log::error!("{}", e);
            if verbose > 0 {
                for cause in e.chain().skip(1) {
                    log::error!("  Caused by: {}", cause);
                }
            }
            exit_code::EXIT_MISCONFIGURATION
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_manifest_parser::ResolverError;

    #[test]
    fn resolve_with_cause_preserves_pip_lock_in_anyhow_chain() {
        let err = ResolverError::ResolveWithCause {
            message: vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
                .to_string(),
            cause: Box::new(ResolverError::Resolve(
                "pip lock failed for /proj/requirements.txt: ERROR: No matching distribution".to_string(),
            )),
        };
        let wrapped: anyhow::Error = err.into();
        let with_ctx = wrapped
            .context("Resolving dependencies for \"/proj/requirements.txt\"");
        let chain: Vec<String> = with_ctx
            .chain()
            .map(std::string::ToString::to_string)
            .collect();
        assert!(
            chain.iter().any(|m| m.contains("pip lock failed")),
            "expected pip lock in anyhow chain, got: {chain:?}"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn run_main_unknown_provider_returns_2() {
        let _guard = crate::registry::registry_test_mutex()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let code = run_main_from_args([
            "vlz",
            "scan",
            "--provider",
            "nonexistentprovider",
            "--offline",
            "/tmp",
        ])
        .await;
        assert_eq!(
            code, 2,
            "unknown provider should yield exit code 2 (FR-019)"
        );
    }

    #[test]
    fn panic_message_extracts_str_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(panic_message(&payload), "boom");
    }

    #[test]
    fn exit_code_from_join_result_maps_panic_to_internal_error() {
        let join = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                tokio::spawn(async {
                    panic!("test panic");
                })
                .await
            })
            .unwrap_err();
        assert_eq!(
            exit_code_from_join_result(Err(join)),
            exit_code::EXIT_INTERNAL_ERROR
        );
    }

    #[tokio::test]
    async fn run_main_help_exits_0() {
        let code = run_main_from_args(["vlz", "--help"]).await;
        assert_eq!(code, 0, "OP-012: --help must exit 0");
    }

    #[tokio::test]
    async fn run_main_version_exits_0() {
        let code = run_main_from_args(["vlz", "--version"]).await;
        assert_eq!(code, 0, "OP-012: --version must exit 0");
    }
}
