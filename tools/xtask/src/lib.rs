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

use std::{fs, io::Write, path::Path};

use ignore::Walk;

/// Read entire file as bytes.
pub fn read_file_bytes(p: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(p)
}

/// Write bytes to path only if content differs. Returns true if written.
pub fn write_if_changed(path: &Path, new: &[u8]) -> std::io::Result<bool> {
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

/// Process one file: ensure it starts with header; optionally replace.
/// Returns Ok(Some(message)) when a difference was found (and possibly changed),
/// Ok(None) when no difference, Err on IO error.
pub fn process_file(
    path: &Path,
    header: &[u8],
    do_replace: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
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

/// Run header check/replace over root. Returns exit code (0 or 1).
pub fn run(
    root: &Path,
    header_path: &Path,
    do_replace: bool,
    do_check: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    run_with_walk(
        root,
        header_path,
        do_replace,
        do_check,
        Walk::new(root).into_iter(),
    )
}

/// Run with a custom walk (e.g. WalkBuilder for tests that need to skip gitignore).
#[doc(hidden)]
pub fn run_with_walk<I>(
    _root: &Path,
    header_path: &Path,
    do_replace: bool,
    do_check: bool,
    walk: I,
) -> Result<i32, Box<dyn std::error::Error>>
where
    I: Iterator<Item = Result<ignore::DirEntry, ignore::Error>>,
{
    let header = fs::read(header_path)?;
    let mut problems: Vec<String> = Vec::new();
    let mut updated = 0usize;

    for entry in walk.filter_map(Result::ok) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        match process_file(&p, &header, do_replace)? {
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
        Ok(0)
    } else if do_check {
        if !problems.is_empty() {
            for p in &problems {
                println!("{}", p);
            }
            eprintln!(
                "{} file(s) missing or with incorrect header.",
                problems.len()
            );
            Ok(1)
        } else {
            println!("All files have the correct header.");
            Ok(0)
        }
    } else {
        if !problems.is_empty() {
            for p in &problems {
                println!("{}", p);
            }
            println!(
                "{} file(s) missing or with incorrect header. Run `cargo run -p xtask -- replace` to fix.",
                problems.len()
            );
        } else {
            println!("All files already start with ci/header.txt content.");
        }
        Ok(0)
    }
}

/// Preserve BOM and a single leading shebang line.
/// Returns (preserve_prefix_len, remainder_slice)
pub fn find_insert_pos_and_remainder(bytes: &[u8]) -> (usize, &[u8]) {
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
/// - line comments that start with "//" but NOT "///" or "//!" doc
pub fn strip_leading_line_comments_only_len(remainder: &[u8]) -> usize {
    let mut i = 0usize;
    let len = remainder.len();

    while i < len {
        let line_end = match remainder[i..].iter().position(|&b| b == b'\n') {
            Some(pos) => i + pos + 1,
            None => len,
        };
        let line = &remainder[i..line_end];

        let is_blank = line
            .iter()
            .all(|&b| b == b'\n' || b == b'\r' || b == b' ' || b == b'\t');

        let mut j = 0usize;
        while j < line.len() && (line[j] == b' ' || line[j] == b'\t' || line[j] == b'\r') {
            j += 1;
        }

        let is_double_slash = line.len() >= j + 2 && line[j] == b'/' && line[j + 1] == b'/';
        let is_triple =
            line.len() >= j + 3 && line[j] == b'/' && line[j + 1] == b'/' && line[j + 2] == b'/';
        let is_bang_doc =
            line.len() >= j + 3 && line[j] == b'/' && line[j + 1] == b'!' && line[j + 2] == b'/';

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

/// Build new file bytes: preserve prefix (BOM/shebang), then header, then remainder without stripped comments.
pub fn build_new_bytes(bytes: &[u8], header: &[u8]) -> Vec<u8> {
    let (preserve_len, remainder) = find_insert_pos_and_remainder(bytes);
    let strip_len = strip_leading_line_comments_only_len(remainder);
    let mut new =
        Vec::with_capacity(preserve_len + header.len() + remainder.len().saturating_sub(strip_len));
    new.extend_from_slice(&bytes[..preserve_len]);
    new.extend_from_slice(header);
    new.extend_from_slice(&remainder[strip_len..]);
    new
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn read_file_bytes_ok() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();
        let bytes = read_file_bytes(f.path()).unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn read_file_bytes_missing() {
        let p = std::path::Path::new("/nonexistent/path/12345");
        assert!(read_file_bytes(p).is_err());
    }

    #[test]
    fn write_if_changed_when_different() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"a").unwrap();
        f.flush().unwrap();
        let path = f.path();
        let ok = write_if_changed(path, b"b").unwrap();
        assert!(ok);
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes, b"b");
    }

    #[test]
    fn write_if_changed_when_same() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"a").unwrap();
        f.flush().unwrap();
        let ok = write_if_changed(f.path(), b"a").unwrap();
        assert!(!ok);
    }

    #[test]
    fn process_file_needs_update_no_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.rs");
        std::fs::write(&path, b"fn main() {}").unwrap();
        let header = b"// header\n";
        let res = process_file(&path, header, false).unwrap();
        assert!(res.is_some());
        assert!(res.unwrap().contains("missing/incorrect header"));
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes, b"fn main() {}");
    }

    #[test]
    fn process_file_needs_update_with_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.rs");
        std::fs::write(&path, b"fn main() {}").unwrap();
        let header = b"// header\n";
        let res = process_file(&path, header, true).unwrap();
        assert!(res.is_some());
        assert!(res.unwrap().contains("updated:"));
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes, b"// header\nfn main() {}");
    }

    #[test]
    fn process_file_already_correct() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.rs");
        let header = b"// header\n";
        let content = build_new_bytes(b"fn main() {}", header);
        std::fs::write(&path, &content).unwrap();
        let res = process_file(&path, header, false).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn run_check_with_problems() {
        let dir = tempfile::tempdir().unwrap();
        let header_path = dir.path().join("header.txt");
        std::fs::write(&header_path, b"// header\n").unwrap();
        let rs = dir.path().join("foo.rs");
        std::fs::write(&rs, b"fn main() {}").unwrap();
        let code = run(dir.path(), &header_path, false, true).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn run_check_no_problems() {
        let dir = tempfile::tempdir().unwrap();
        let header_path = dir.path().join("header.txt");
        std::fs::write(&header_path, b"// header\n").unwrap();
        let rs = dir.path().join("foo.rs");
        let content = build_new_bytes(b"fn main() {}", b"// header\n");
        std::fs::write(&rs, &content).unwrap();
        let code = run(dir.path(), &header_path, false, true).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn run_replace_updates_file() {
        let dir = tempfile::tempdir().unwrap();
        let header_path = dir.path().join("header.txt");
        std::fs::write(&header_path, b"// header\n").unwrap();
        let rs = dir.path().join("foo.rs");
        std::fs::write(&rs, b"fn main() {}").unwrap();
        let code = run(dir.path(), &header_path, true, false).unwrap();
        assert_eq!(code, 0);
        let bytes = std::fs::read(&rs).unwrap();
        assert_eq!(bytes, b"// header\nfn main() {}");
    }

    #[test]
    fn run_inspect_with_problems() {
        let dir = tempfile::tempdir().unwrap();
        let header_path = dir.path().join("header.txt");
        std::fs::write(&header_path, b"// header\n").unwrap();
        let rs = dir.path().join("foo.rs");
        std::fs::write(&rs, b"fn main() {}").unwrap();
        let walk = ignore::WalkBuilder::new(dir.path())
            .git_ignore(false)
            .build()
            .into_iter();
        let code = run_with_walk(dir.path(), &header_path, false, false, walk).unwrap();
        assert_eq!(code, 0);
        let bytes = std::fs::read(&rs).unwrap();
        assert_eq!(bytes, b"fn main() {}", "inspect mode must not mutate");
    }

    #[test]
    fn run_inspect_no_problems() {
        let dir = tempfile::tempdir().unwrap();
        let header_path = dir.path().join("header.txt");
        std::fs::write(&header_path, b"// header\n").unwrap();
        let rs = dir.path().join("foo.rs");
        let content = build_new_bytes(b"fn main() {}", b"// header\n");
        std::fs::write(&rs, &content).unwrap();
        let walk = ignore::WalkBuilder::new(dir.path())
            .git_ignore(false)
            .build()
            .into_iter();
        let code = run_with_walk(dir.path(), &header_path, false, false, walk).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn find_insert_pos_no_bom_no_shebang() {
        let b = b"fn main() {}";
        let (pos, rem) = find_insert_pos_and_remainder(b);
        assert_eq!(pos, 0);
        assert_eq!(rem, b"fn main() {}");
    }

    #[test]
    fn find_insert_pos_shebang() {
        let b = b"#!/usr/bin/env rustx\nfn main() {}";
        let (pos, rem) = find_insert_pos_and_remainder(b);
        assert_eq!(pos, 21, "shebang line length including newline");
        assert_eq!(rem, b"fn main() {}");
    }

    #[test]
    fn find_insert_pos_bom_then_shebang() {
        let b = b"\xef\xbb\xbf#!/bin/true\ncode";
        let (pos, rem) = find_insert_pos_and_remainder(b);
        assert_eq!(pos, 15, "BOM (3) + shebang line including newline (12)");
        assert_eq!(rem, b"code");
    }

    #[test]
    fn find_insert_pos_shebang_no_newline() {
        let b = b"#!/usr/bin/env bash";
        let (pos, rem) = find_insert_pos_and_remainder(b);
        assert_eq!(pos, 0);
        assert_eq!(rem, b"#!/usr/bin/env bash");
    }

    #[test]
    fn strip_leading_blank_lines() {
        let b = b"\n\n  \n\t\n";
        assert_eq!(strip_leading_line_comments_only_len(b), b.len());
    }

    #[test]
    fn strip_leading_line_comment_not_doc() {
        let b = b"// comment\n// another\nfn main() {}";
        assert_eq!(strip_leading_line_comments_only_len(b), 22);
    }

    #[test]
    fn strip_leading_doc_comment_not_stripped() {
        let b = b"/// doc comment\nfn main() {}";
        assert_eq!(strip_leading_line_comments_only_len(b), 0);
    }

    #[test]
    fn strip_leading_line_comment_no_newline() {
        let b = b"// comment";
        assert_eq!(strip_leading_line_comments_only_len(b), 10);
    }

    #[test]
    fn strip_leading_bang_doc_not_stripped() {
        let b = b"/!/ something\nfn main() {}";
        assert_eq!(strip_leading_line_comments_only_len(b), 0);
    }

    #[test]
    fn build_new_bytes_no_prefix() {
        let bytes = b"fn main() {}";
        let header = b"// header\n";
        let new = build_new_bytes(bytes, header);
        assert_eq!(new, b"// header\nfn main() {}");
    }

    #[test]
    fn build_new_bytes_strips_leading_comment() {
        let bytes = b"// old comment\nfn main() {}";
        let header = b"// header\n";
        let new = build_new_bytes(bytes, header);
        assert_eq!(new, b"// header\nfn main() {}");
    }

    #[test]
    fn build_new_bytes_with_bom() {
        let bytes = b"\xef\xbb\xbffn main() {}";
        let header = b"// header\n";
        let new = build_new_bytes(bytes, header);
        assert_eq!(new, b"\xef\xbb\xbf// header\nfn main() {}");
    }

    #[test]
    fn build_new_bytes_with_shebang() {
        let bytes = b"#!/usr/bin/env rustx\nfn main() {}";
        let header = b"// header\n";
        let new = build_new_bytes(bytes, header);
        assert_eq!(new, b"#!/usr/bin/env rustx\n// header\nfn main() {}");
    }

    #[test]
    fn process_file_nonexistent_path() {
        let p = std::path::Path::new("/nonexistent/path/12345.rs");
        let header = b"// header\n";
        assert!(process_file(p, header, false).is_err());
    }

    #[test]
    fn write_if_changed_nonexistent_path() {
        let p = std::path::Path::new("/nonexistent/path/12345");
        assert!(write_if_changed(p, b"content").is_err());
    }
}
