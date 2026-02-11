// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
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

use std::{fs, io::Write, path::Path};
use ignore::Walk;

use xtask::build_new_bytes;

const HEADER_FILE: &str = "tools/header.txt";

fn load_header_bytes() -> Vec<u8> {
    fs::read(HEADER_FILE).expect("reading header file")
}

fn read_file_bytes(p: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(p)
}

fn write_if_changed(path: &Path, new: &[u8]) -> std::io::Result<bool> {
    let old = fs::read(path)?;
    if old == new {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(new)?;
    Ok(true)
}

fn process_file(
    path: &Path,
    header: &[u8],
    do_replace: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Returns Ok(Some(message)) when a difference was found (and possibly changed),
    // Ok(None) when no difference, Err on IO error.
    let bytes = read_file_bytes(path)?;
    let new = build_new_bytes(&bytes, header);

    if new != bytes {
        if do_replace {
            write_if_changed(path, &new)?;
            Ok(Some(format!("updated: {}", path.display())))
        } else {
            Ok(Some(format!(
                "missing/incorrect header: {}",
                path.display()
            )))
        }
    } else {
        Ok(None)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let do_replace = args.iter().any(|a| a == "replace");
    let do_check = args.iter().any(|a| a == "check");

    let header = load_header_bytes();
    let mut problems: Vec<String> = Vec::new();
    let mut updated = 0usize;

    for entry in Walk::new(".").into_iter().filter_map(Result::ok) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        match process_file(p, &header, do_replace)? {
            Some(msg) => {
                if do_replace {
                    updated += 1;
                    println!("{}", msg);
                } else {
                    problems.push(msg);
                }
            }
            None => {}
        }
    }

    if do_replace {
        println!("Updated {} file(s).", updated);
        if updated > 0 {
            std::process::exit(0);
        } else {
            std::process::exit(0);
        }
    } else if do_check {
        if !problems.is_empty() {
            for p in &problems {
                println!("{}", p);
            }
            eprintln!(
                "{} file(s) missing or with incorrect header.",
                problems.len()
            );
            std::process::exit(1);
        } else {
            println!("All files have the correct header.");
            std::process::exit(0);
        }
    } else {
        if !problems.is_empty() {
            for p in &problems {
                println!("{}", p);
            }
            println!("{} file(s) missing or with incorrect header. Run `cargo run -p xtask -- replace` to fix.", problems.len());
        } else {
            println!("All files already start with ci/header.txt content.");
        }
        Ok(())
    }
}
