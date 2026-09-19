// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    afl::fuzz(true, |data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = vlz_exploitability::parse_kev_catalog(s);
            let _ = vlz_exploitability::parse_kev_csv(s);
        }
    });
}
