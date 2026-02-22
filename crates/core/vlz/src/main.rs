// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

#[tokio::main]
async fn main() {
    let code = vlz::run_main().await;
    std::process::exit(code);
}
