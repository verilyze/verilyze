// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz harness for `setup.py` AST parsing (NFR-020, SEC-017).
//!
//! Calls `parse_setup_py`, which applies a pre-parse resource guard before Ruff.
//! Residual risk: pathological input below the guard thresholds may still exhaust
//! the native stack inside `ruff_python_parser` (recursive descent), which aborts
//! the process rather than returning `Err`.

fn main() {
    afl::fuzz(true, |data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = vlz_python::parse_setup_py(s);
                }));
        }
    });
}
