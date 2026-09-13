// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared advisory-symbol sanitization and line matching for Tier C evidence.

use crate::{MAX_REACHABILITY_EVIDENCE_PER_CVE, ReachabilityEvidence};

/// Maximum advisory symbols accepted per CVE from provider metadata.
pub const MAX_ADVISORY_SYMBOLS: usize = 64;

/// Maximum length of a single advisory symbol string.
pub const MAX_ADVISORY_SYMBOL_LEN: usize = 512;

/// Comment style for stripping lines before symbol matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineCommentStyle {
    Hash,
    SlashSlash,
}

/// Drop empty, whitespace-only, or oversized symbols; cap count (provider input).
pub fn sanitize_advisory_symbols(symbols: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for sym in symbols {
        let trimmed = sym.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_ADVISORY_SYMBOL_LEN {
            continue;
        }
        if out.iter().any(|s| s == trimmed) {
            continue;
        }
        out.push(trimmed.to_string());
        if out.len() >= MAX_ADVISORY_SYMBOLS {
            break;
        }
    }
    out
}

/// True when no more evidence sites should be collected for one CVE.
pub fn reachability_evidence_at_cap(
    evidence: &[ReachabilityEvidence],
) -> bool {
    evidence.len() >= MAX_REACHABILITY_EVIDENCE_PER_CVE
}

/// Sort and truncate evidence deterministically (path, line, symbol).
pub fn cap_reachability_evidence(evidence: &mut Vec<ReachabilityEvidence>) {
    evidence.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.start_line.cmp(&b.start_line))
            .then(a.symbol.cmp(&b.symbol))
    });
    evidence.dedup_by(|a, b| {
        a.path == b.path
            && a.start_line == b.start_line
            && a.symbol == b.symbol
    });
    evidence.truncate(MAX_REACHABILITY_EVIDENCE_PER_CVE);
}

/// Code portion of a source line for symbol matching (comments/strings removed).
/// The original line number is unchanged; only the match predicate uses this view.
pub fn line_code_for_symbol_match(
    line: &str,
    style: LineCommentStyle,
) -> String {
    let without_comment = strip_line_comment(line, style);
    remove_quoted_regions(without_comment.trim())
}

/// Strip `//` and `/* */` comments from C-like source while preserving newlines.
///
/// String and character literals are left intact so comment markers inside
/// quotes do not open or close comments. Comment bodies are replaced with
/// spaces (newlines kept) so line numbers stay stable for evidence.
///
/// Shared by Java/Kotlin reachability and available for other C-like languages.
pub fn scrub_c_style_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_block = false;
    let mut in_line = false;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                out.push(' ');
                out.push(' ');
                in_block = false;
            } else if c == '\n' {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if let Some(quote) = in_string {
            out.push(c);
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == quote {
                in_string = None;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = Some(c);
            out.push(c);
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            out.push(' ');
            out.push(' ');
            in_line = true;
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            out.push(' ');
            out.push(' ');
            in_block = true;
            continue;
        }
        out.push(c);
    }
    out
}

/// Whether `sym` appears in `code` with identifier/path boundaries.
pub fn qualified_symbol_in_code(code: &str, sym: &str) -> bool {
    if sym.is_empty() {
        return false;
    }
    if sym.contains('.') || sym.contains('/') || sym.contains("::") {
        return symbol_match_at_boundaries(code, sym);
    }
    symbol_match_at_boundaries(code, sym)
        || member_access_symbol_in_code(code, sym)
}

fn member_access_symbol_in_code(code: &str, sym: &str) -> bool {
    let needle = format!(".{sym}");
    let mut start = 0usize;
    while let Some(pos) = code[start..].find(&needle) {
        let after = start + pos + needle.len();
        if after >= code.len()
            || !is_identifier_continue(code.as_bytes()[after])
        {
            return true;
        }
        start = start + pos + 1;
    }
    false
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn symbol_match_at_boundaries(code: &str, sym: &str) -> bool {
    let mut start = 0usize;
    while let Some(pos) = code[start..].find(sym) {
        let idx = start + pos;
        let before_ok =
            idx == 0 || !is_symbol_boundary_continue(code.as_bytes()[idx - 1]);
        let after_idx = idx + sym.len();
        let after_ok = after_idx >= code.len()
            || !is_symbol_boundary_continue(code.as_bytes()[after_idx]);
        if before_ok && after_ok {
            return true;
        }
        start = idx + sym.len().max(1);
    }
    false
}

fn is_symbol_boundary_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':')
}

fn strip_line_comment(line: &str, style: LineCommentStyle) -> &str {
    match style {
        LineCommentStyle::Hash => {
            line.split_once('#').map_or(line, |(a, _)| a)
        }
        LineCommentStyle::SlashSlash => {
            let bytes = line.as_bytes();
            let mut in_quote = None::<u8>;
            let mut escaped = false;
            for (i, &b) in bytes.iter().enumerate() {
                if let Some(q) = in_quote {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if b == b'\\' {
                        escaped = true;
                        continue;
                    }
                    if b == q {
                        in_quote = None;
                    }
                    continue;
                }
                if b == b'"' || b == b'\'' || b == b'`' {
                    in_quote = Some(b);
                    continue;
                }
                if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    return &line[..i];
                }
            }
            line
        }
    }
}

fn remove_quoted_regions(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' || c == '`' {
            out.push(' ');
            let mut escaped = false;
            for ch in chars.by_ref() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == c {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sanitize_drops_empty_and_caps_count() {
        let input: Vec<String> = (0..100).map(|i| format!("sym{i}")).collect();
        let out = sanitize_advisory_symbols(&input);
        assert_eq!(out.len(), MAX_ADVISORY_SYMBOLS);
    }

    #[test]
    fn qualified_symbol_rejects_substring() {
        let code = "not_my_pkg.submod.vuln_fn_extra()";
        assert!(!qualified_symbol_in_code(code, "pkg.submod.vuln_fn"));
    }

    #[test]
    fn line_code_ignores_string_literal_but_keeps_line() {
        let code = line_code_for_symbol_match(
            "x = \"pkg.submod.vuln_fn\"  # pkg.submod.vuln_fn",
            LineCommentStyle::Hash,
        );
        assert!(!qualified_symbol_in_code(&code, "pkg.submod.vuln_fn"));
    }

    #[test]
    fn scrub_c_style_strips_line_and_block_comments() {
        let scrubbed = scrub_c_style_comments(
            "import a.B;\n// import hide.Me;\n/* import also.Hide; */\nimport c.D;\n",
        );
        assert!(scrubbed.contains("import a.B;"));
        assert!(scrubbed.contains("import c.D;"));
        assert!(!scrubbed.contains("hide.Me"));
        assert!(!scrubbed.contains("also.Hide"));
        assert_eq!(scrubbed.lines().count(), 4);
    }

    #[test]
    fn scrub_c_style_keeps_comment_markers_inside_strings() {
        let scrubbed = scrub_c_style_comments(
            "String a = \"/*\";\nimport com.example.Keep;\nString b = \"*/\";\n",
        );
        assert!(scrubbed.contains("import com.example.Keep;"));
        assert!(scrubbed.contains("\"/*\""));
    }

    #[test]
    fn scrub_c_style_line_comment_does_not_open_block() {
        let scrubbed =
            scrub_c_style_comments("// decoy /*\nimport com.example.Real;\n");
        assert!(scrubbed.contains("import com.example.Real;"));
        assert!(!scrubbed.contains("decoy"));
    }

    #[test]
    fn cap_evidence_sorts_deterministically() {
        let mut evidence = vec![
            ReachabilityEvidence {
                path: PathBuf::from("b.rs"),
                start_line: 2,
                end_line: None,
                symbol: "sym".to_string(),
            },
            ReachabilityEvidence {
                path: PathBuf::from("a.rs"),
                start_line: 1,
                end_line: None,
                symbol: "sym".to_string(),
            },
        ];
        cap_reachability_evidence(&mut evidence);
        assert_eq!(evidence[0].path, PathBuf::from("a.rs"));
    }
}
