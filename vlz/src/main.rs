// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use log::error;

use vlz::cli::Cli;
use vlz::run::{is_broken_pipe, log_level_from_verbosity_count, run};

#[tokio::main]
async fn main() -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");
    let log_filter = log_level_from_verbosity_count(std::env::args().filter(|a| a == "-v").count());
    env_logger::Builder::from_env(env)
        .filter_level(log_filter)
        .init();

    let args = Cli::parse();
    let verbose = args.verbose;
    let code = run(args).await.unwrap_or_else(|e| {
        if is_broken_pipe(&e) {
            0
        } else {
            error!("{}", e);
            if verbose > 0 {
                for cause in e.chain().skip(1) {
                    error!("  Caused by: {}", cause);
                }
            }
            2
        }
    });
    std::process::exit(code);
}
