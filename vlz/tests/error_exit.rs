// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration test: vlz scan with invalid provider exits with code 2 (FR-019).

use std::process::Command;

#[test]
fn scan_unknown_provider_exits_2() {
    let status = Command::new(env!("CARGO_BIN_EXE_vlz"))
        .args([
            "scan",
            "--provider",
            "nonexistentprovider",
            "--offline",
            "/tmp",
        ])
        .env("XDG_CONFIG_HOME", "/tmp/vlz-test-cfg")
        .env("XDG_CACHE_HOME", "/tmp/vlz-test-cache")
        .env("XDG_DATA_HOME", "/tmp/vlz-test-data")
        .status()
        .expect("failed to execute vlz");

    assert!(
        !status.success(),
        "vlz scan --provider nonexistentprovider should fail"
    );
    assert_eq!(
        status.code(),
        Some(2),
        "expected exit code 2 for unknown provider (FR-019)"
    );
}
