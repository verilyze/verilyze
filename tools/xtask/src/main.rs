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

/****************************************************************************/

use std::path::Path;

const HEADER_FILE: &str = "tools/header.txt";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let do_replace = args.iter().any(|a| a == "replace");
    let do_check = args.iter().any(|a| a == "check");

    let root = std::env::var("XTASK_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Path::new(".").to_path_buf());
    let header_path = root.join(HEADER_FILE);

    let code = xtask::run(
        &root,
        &header_path,
        do_replace,
        do_check,
    )
    .unwrap_or_else(|e| {
        eprintln!("{}", e);
        1
    });
    std::process::exit(code);
}
