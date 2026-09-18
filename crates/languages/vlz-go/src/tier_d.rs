// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Go Tier D: import-aware selector matching (FR-032).
//!
//! Selector heuristic only -- not a Go parser or call graph. Callers treat
//! dot-imports and blank imports as unknown (never not-reachable).

/// 1-based lines where any `local.ident` selector appears in `content`.
pub fn selector_match_lines(
    content: &str,
    locals: &[String],
    ident: &str,
) -> Vec<u32> {
    if locals.is_empty() || ident.is_empty() {
        return Vec::new();
    }
    let stripped = strip_go_comments_and_strings(content);
    let mut lines = Vec::new();
    for (idx, line) in stripped.lines().enumerate() {
        if locals
            .iter()
            .any(|local| line_has_selector(line, local, ident))
        {
            lines.push((idx + 1) as u32);
        }
    }
    lines
}

/// Trailing identifier of an advisory symbol (`pkg.Type` -> `Type`).
pub fn trailing_go_ident(symbol: &str) -> Option<&str> {
    let ident = symbol.rsplit(['.', '/']).next().unwrap_or(symbol);
    if ident.is_empty() || ident.contains('/') {
        return None;
    }
    let first = ident.chars().next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    if !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(ident)
}

/// Import path prefix of `path.Ident` symbols, if present.
#[cfg(test)]
pub fn symbol_import_path(symbol: &str) -> Option<&str> {
    let (head, ident) = symbol.rsplit_once('.')?;
    if ident.is_empty() || head.is_empty() || ident.contains('/') {
        return None;
    }
    Some(head)
}

fn strip_go_comments_and_strings(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_raw = false;
    let mut in_interp = false;
    let mut escape = false;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
            i += 1;
            continue;
        }
        if in_block_comment {
            if c == '*' && next == Some('/') {
                out.push(' ');
                out.push(' ');
                i += 2;
                in_block_comment = false;
                continue;
            }
            out.push(if c == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        if in_raw {
            if c == '`' {
                in_raw = false;
            }
            out.push(if c == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        if in_interp {
            if escape {
                escape = false;
                out.push(' ');
                i += 1;
                continue;
            }
            if c == '\\' {
                escape = true;
                out.push(' ');
                i += 1;
                continue;
            }
            if c == '"' {
                in_interp = false;
            }
            out.push(if c == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            in_line_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }
        if c == '/' && next == Some('*') {
            in_block_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }
        if c == '`' {
            in_raw = true;
            out.push(' ');
            i += 1;
            continue;
        }
        if c == '"' {
            in_interp = true;
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn line_has_selector(line: &str, local: &str, ident: &str) -> bool {
    if local.is_empty() {
        return false;
    }
    let needle = format!("{local}.{ident}");
    let bytes = line.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while start + needle_bytes.len() <= bytes.len() {
        if bytes[start..].starts_with(needle_bytes)
            && !ident_char_before(bytes, start)
            && !ident_char_after(bytes, start + needle_bytes.len())
        {
            return true;
        }
        start += 1;
    }
    false
}

fn ident_char_before(bytes: &[u8], start: usize) -> bool {
    start > 0 && is_ident_byte(bytes[start - 1])
}

fn ident_char_after(bytes: &[u8], end: usize) -> bool {
    end < bytes.len() && is_ident_byte(bytes[end])
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_match_finds_alias_call() {
        let src = "package main\nfunc main() { alias.Vuln() }\n";
        assert_eq!(
            selector_match_lines(src, &["alias".to_string()], "Vuln"),
            vec![2]
        );
    }

    #[test]
    fn selector_match_ignores_comment_and_string() {
        let src = "func main() {\n  // bar.Vuln\n  s := \"bar.Vuln\"\n}\n";
        assert!(
            selector_match_lines(src, &["bar".to_string()], "Vuln").is_empty()
        );
    }

    #[test]
    fn trailing_ident_from_qualified_symbol() {
        assert_eq!(trailing_go_ident("github.com/foo/bar.Vuln"), Some("Vuln"));
        assert_eq!(
            symbol_import_path("github.com/foo/bar.Vuln"),
            Some("github.com/foo/bar")
        );
    }

    #[test]
    fn selector_match_skips_empty_locals_or_ident() {
        let src = "func main() { bar.Vuln() }\n";
        assert!(selector_match_lines(src, &[], "Vuln").is_empty());
        assert!(
            selector_match_lines(src, &["bar".to_string()], "").is_empty()
        );
        assert!(
            selector_match_lines(src, &[String::new()], "Vuln").is_empty()
        );
    }

    #[test]
    fn trailing_ident_and_import_path_reject_invalid() {
        assert_eq!(trailing_go_ident(""), None);
        assert_eq!(trailing_go_ident("."), None);
        assert_eq!(trailing_go_ident("9Bad"), None);
        assert_eq!(trailing_go_ident("pkg.bad-name"), None);
        assert_eq!(symbol_import_path("nosplit"), None);
        assert_eq!(symbol_import_path("head."), None);
        assert_eq!(symbol_import_path(".Ident"), None);
        assert_eq!(symbol_import_path("head.in/ident"), None);
    }

    #[test]
    fn selector_match_ignores_block_comment_raw_and_escape() {
        let src = concat!(
            "func main() {\n",
            "  /* bar.Vuln */\n",
            "  s := `bar.Vuln`\n",
            "  t := \"bar.\\\"Vuln\"\n",
            "}\n",
        );
        assert!(
            selector_match_lines(src, &["bar".to_string()], "Vuln").is_empty()
        );
    }
}
