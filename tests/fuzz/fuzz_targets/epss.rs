// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    afl::fuzz(true, |data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = vlz_exploitability::parse_epss_json(s);
            let _ = vlz_exploitability::parse_epss_csv(s);
            let _ = vlz_exploitability::EpssIndex::from_snapshot_json(s);
        }
    });
}
