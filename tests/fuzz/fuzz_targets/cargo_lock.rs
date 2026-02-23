// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    afl::fuzz(true, |data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = vlz_rust::parse_cargo_lock(s);
                }));
        }
    });
}
