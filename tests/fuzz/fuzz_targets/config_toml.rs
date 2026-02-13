// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

use std::io::Read;

fn main() {
    // Subprocess mode: parse stdin and exit (0=ok, 1=error). Child crashes are isolated.
    if std::env::args().nth(1).as_deref() == Some("--parse-stdin") {
        let mut input = String::new();
        let _ = std::io::stdin().read_to_string(&mut input);
        let status = spd::config::parse_and_validate_toml(&input);
        std::process::exit(status.is_err() as i32);
    }

    afl::fuzz(true, |data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            // Run parser in subprocess; crashes (abort, segfault) are isolated (SEC-017).
            let exe = std::env::current_exe().expect("current_exe");
            let mut child = std::process::Command::new(&exe)
                .arg("--parse-stdin")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn");
            let mut stdin = child.stdin.take().expect("stdin");
            let _ = std::io::Write::write_all(&mut stdin, s.as_bytes());
            drop(stdin);
            let _ = child.wait();
        }
    });
}
