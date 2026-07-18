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
