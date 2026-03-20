// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

#[tokio::main]
async fn main() {
    vlz_cve_client::ensure_crypto_provider();
    let code = vlz::run_main().await;
    std::process::exit(code);
}
