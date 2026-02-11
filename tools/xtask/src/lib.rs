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
    use super::*;

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
}
