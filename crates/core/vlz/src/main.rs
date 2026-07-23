// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

#[tokio::main]
async fn main() {
    vlz_cve_client::ensure_crypto_provider();
    let args: Vec<String> = std::env::args().collect();
    let code = vlz::exit_code_from_join_result(
        tokio::spawn(vlz::run_main_from_args(args)).await,
    );
    std::process::exit(code);
}
