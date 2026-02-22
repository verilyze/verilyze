// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use clap::Parser;

pub mod cli;
pub mod config;
pub mod registry;
pub mod run;

#[cfg(any(test, feature = "testing"))]
pub mod mocks;

pub use run::run;

/// Entry point logic: init logger, parse CLI, run command, return exit code.
/// Used by the binary.
pub async fn run_main() -> i32 {
    run_main_from_args(std::env::args()).await
}

/// Same as run_main but accepts args. Used by run_main() and by tests.
fn run_main_from_args<I, T>(args: I) -> impl std::future::Future<Output = i32>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone + AsRef<std::ffi::OsStr>,
{
    async move {
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");
    let args_vec: Vec<_> = args.into_iter().collect();
    let verbose_count = args_vec
        .iter()
        .filter(|a| Into::<std::ffi::OsString>::into((*a).clone()).to_string_lossy() == "-v")
        .count();
    let log_filter = run::log_level_from_verbosity_count(verbose_count);
    env_logger::Builder::from_env(env)
        .filter_level(log_filter)
        .init();

    let args = match cli::Cli::try_parse_from(args_vec) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            return 2;
        }
    };
    let verbose = args.verbose;
    run(args).await.unwrap_or_else(|e| {
        if run::is_broken_pipe(&e) {
            0
        } else {
            log::error!("{}", e);
            if verbose > 0 {
                for cause in e.chain().skip(1) {
                    log::error!("  Caused by: {}", cause);
                }
            }
            2
        }
    })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_main_unknown_provider_returns_2() {
        let code = run_main_from_args([
            "vlz",
            "scan",
            "--provider",
            "nonexistentprovider",
            "--offline",
            "/tmp",
        ])
        .await;
        assert_eq!(code, 2, "unknown provider should yield exit code 2 (FR-019)");
    }
}
