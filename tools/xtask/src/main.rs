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

/****************************************************************************/

use std::{fs, io::Write, path::Path};
use walkdir::WalkDir;

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

/// Preserve BOM and a single leading shebang line.
/// Returns (preserve_prefix_len, remainder_slice)
fn find_insert_pos_and_remainder<'a>(bytes: &'a [u8]) -> (usize, &'a [u8]) {
    let mut pos = 0usize;
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        pos = 3;
    }
    if bytes.len() > pos + 1 && &bytes[pos..pos + 2] == b"#!" {
        if let Some(i) = bytes[pos..].iter().position(|&b| b == b'\n') {
            pos += i + 1;
        } else {
            return (pos, &bytes[pos..]);
        }
    }
    (pos, &bytes[pos..])
}

/// Determine length of a leading block consisting only of:
/// - blank lines, or
/// - line comments that start with "//" but NOT "///" or "///" doc or "//!"
fn strip_leading_line_comments_only_len(remainder: &[u8]) -> usize {
    let mut i = 0usize;
    let len = remainder.len();

    while i < len {
        // find end of current line
        let line_end = match remainder[i..].iter().position(|&b| b == b'\n') {
            Some(pos) => i + pos + 1,
            None => len,
        };
        let line = &remainder[i..line_end];

        // check if line is blank (spaces/tabs followed by newline or empty)
        let is_blank = line
            .iter()
            .all(|&b| b == b'\n' || b == b'\r' || b == b' ' || b == b'\t');

        // check for line comment start after optional leading spaces/tabs
        let mut j = 0usize;
        while j < line.len() && (line[j] == b' ' || line[j] == b'\t' || line[j] == b'\r') {
            j += 1;
        }

        let is_double_slash = line.len() >= j + 2 && line[j] == b'/' && line[j + 1] == b'/';
        let is_triple =
            line.len() >= j + 3 && line[j] == b'/' && line[j + 1] == b'/' && line[j + 2] == b'/';
        let is_bang_doc =
            line.len() >= j + 3 && line[j] == b'/' && line[j + 1] == b'!' && line[j + 2] == b'/';

        // Strip only lines that are blank or start with '//' but NOT '///' or '//!'
        let should_strip_line = if is_double_slash {
            !(is_triple || is_bang_doc)
        } else {
            false
        };

        if is_blank || should_strip_line {
            i = line_end;
            continue;
        } else {
            break;
        }
    }

    i
}

fn build_new_bytes(bytes: &[u8], header: &[u8]) -> Vec<u8> {
    let (preserve_len, remainder) = find_insert_pos_and_remainder(bytes);
    let strip_len = strip_leading_line_comments_only_len(remainder);
    let mut new =
        Vec::with_capacity(preserve_len + header.len() + remainder.len().saturating_sub(strip_len));
    new.extend_from_slice(&bytes[..preserve_len]); // BOM/shebang preserved
    new.extend_from_slice(header); // header inserted next, exactly as-is
    new.extend_from_slice(&remainder[strip_len..]); // append remainder (including module-doc comments if present)
    new
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

    for entry in WalkDir::new(".").into_iter().filter_map(Result::ok) {
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
