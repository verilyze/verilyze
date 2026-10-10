// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Dart Tier D: import-binding selector matching (FR-032).
//!
//! First-party only. Heuristic regex, not a full Dart analyzer or call graph.

/// One `package:` import of a pub package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartImportBinding {
    /// Pub package name from the `package:<name>/` URI.
    pub package: String,
    /// `as` prefix when present.
    pub alias: Option<String>,
    /// Identifiers from `show`; empty when the clause is absent.
    pub shown: Vec<String>,
    /// Identifiers from `hide`; empty when the clause is absent.
    pub hidden: Vec<String>,
}

use vlz_reachability_trait::{
    LineCommentStyle, line_code_for_symbol_match, scrub_c_style_comments,
};

/// Trailing identifier of an advisory symbol (`pkg.Cls.method` -> `method`).
pub fn trailing_dart_ident(symbol: &str) -> Option<&str> {
    let ident = symbol.rsplit([':', '.', '/']).next().unwrap_or(symbol);
    let first = ident.chars().next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    if !ident.chars().all(is_ident_char) {
        return None;
    }
    Some(ident)
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn import_regex() -> regex::Regex {
    regex::Regex::new(
        r#"^\s*(?:import|export)\s+['"]package:([a-z_][a-z0-9_]*)/[^'"]*['"]\s*(.*?);"#,
    )
    .expect("valid Dart import regex")
}

fn clause_idents(rest: &str, keyword: &str) -> Vec<String> {
    let pattern = format!(
        r"\b{keyword}\s+([A-Za-z0-9_,\s]+?)(?:\s+(?:show|hide|as|deferred)\b|$)"
    );
    regex::Regex::new(&pattern)
        .ok()
        .and_then(|re| re.captures(rest))
        .map(|caps| {
            caps[1]
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn alias_of(rest: &str) -> Option<String> {
    let re = regex::Regex::new(r"\bas\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid Dart alias regex");
    re.captures(rest).map(|caps| caps[1].to_string())
}

/// Collect `package:` import bindings from Dart source text.
pub fn collect_dart_import_bindings(content: &str) -> Vec<DartImportBinding> {
    let re = import_regex();
    let mut out = Vec::new();
    for line in scrub_c_style_comments(content).lines() {
        let code = line.trim();
        let Some(caps) = re.captures(code) else {
            continue;
        };
        let rest = caps.get(2).map_or("", |m| m.as_str());
        out.push(DartImportBinding {
            package: caps[1].to_string(),
            alias: alias_of(rest),
            shown: clause_idents(rest, "show"),
            hidden: clause_idents(rest, "hide"),
        });
    }
    out
}

fn contains_bounded(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(rel) = line[start..].find(needle) {
        let abs = start + rel;
        let before_ok = abs == 0
            || !(bytes[abs - 1].is_ascii_alphanumeric()
                || bytes[abs - 1] == b'_'
                || bytes[abs - 1] == b'$');
        let after = abs + needle.len();
        let after_ok = after >= bytes.len()
            || !(bytes[after].is_ascii_alphanumeric()
                || bytes[after] == b'_'
                || bytes[after] == b'$');
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

fn ident_visible(binding: &DartImportBinding, ident: &str) -> bool {
    (binding.shown.is_empty() || binding.shown.iter().any(|s| s == ident))
        && !binding.hidden.iter().any(|s| s == ident)
}

/// 1-based lines (excluding import directives) where `ident` is used through
/// the given binding.
pub fn selector_match_lines(
    content: &str,
    binding: &DartImportBinding,
    ident: &str,
) -> Vec<u32> {
    if ident.is_empty() {
        return Vec::new();
    }
    let needle = match &binding.alias {
        Some(alias) => format!("{alias}.{ident}"),
        None if ident_visible(binding, ident) => ident.to_string(),
        None => return Vec::new(),
    };
    let directive = regex::Regex::new(r"^(?:import|export|part)\b")
        .expect("valid Dart directive regex");
    let mut lines = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let code = line_code_for_symbol_match(
            line.trim(),
            LineCommentStyle::SlashSlash,
        );
        if directive.is_match(&code) {
            continue;
        }
        if contains_bounded(&code, &needle) {
            lines.push((idx + 1) as u32);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_ident_extraction() {
        assert_eq!(trailing_dart_ident("Client.get"), Some("get"));
        assert_eq!(
            trailing_dart_ident("package:http/http.dart"),
            Some("dart")
        );
        assert_eq!(trailing_dart_ident("http::get"), Some("get"));
        assert_eq!(trailing_dart_ident("Foo."), None);
        assert_eq!(trailing_dart_ident("1bad"), None);
        assert_eq!(trailing_dart_ident("bad-name"), None);
        assert_eq!(trailing_dart_ident("_priv$"), None);
        assert_eq!(trailing_dart_ident("_ok1"), Some("_ok1"));
    }

    #[test]
    fn bindings_parse_alias_show_hide() {
        let src = "import 'package:http/http.dart' as http;\n\
                   import \"package:collection/collection.dart\" show \
                   IterableExtension, equalsIgnoreAsciiCase;\n\
                   import 'package:meta/meta.dart' hide visibleForTesting;\n\
                   import 'dart:io';\n\
                   import 'package:a/a.dart' deferred as lazy;\n\
                   // import 'package:evil/evil.dart';\n\
                   export 'package:b/b.dart';\n";
        let b = collect_dart_import_bindings(src);
        let pkgs: Vec<_> = b.iter().map(|x| x.package.as_str()).collect();
        assert_eq!(pkgs, ["http", "collection", "meta", "a", "b"]);
        assert_eq!(b[0].alias.as_deref(), Some("http"));
        assert_eq!(b[1].shown, ["IterableExtension", "equalsIgnoreAsciiCase"]);
        assert_eq!(b[2].hidden, ["visibleForTesting"]);
        assert_eq!(b[3].alias.as_deref(), Some("lazy"));
        assert!(b[4].alias.is_none() && b[4].shown.is_empty());
    }

    #[test]
    fn selector_alias_requires_prefix() {
        let src = "import 'package:http/http.dart' as http;\n\
                   void f() {\n  http.get(u);\n  other.get(u);\n  get(u);\n}\n";
        let b = &collect_dart_import_bindings(src)[0];
        assert_eq!(selector_match_lines(src, b, "get"), vec![3]);
    }

    #[test]
    fn selector_unprefixed_honors_show_and_hide() {
        let src = "import 'package:c/c.dart' show Foo;\nFoo();\nBar();\n";
        let b = &collect_dart_import_bindings(src)[0];
        assert_eq!(selector_match_lines(src, b, "Foo"), vec![2]);
        assert!(selector_match_lines(src, b, "Bar").is_empty());
        let src2 = "import 'package:c/c.dart' hide Bar;\nFoo();\nBar();\n";
        let b2 = &collect_dart_import_bindings(src2)[0];
        assert_eq!(selector_match_lines(src2, b2, "Foo"), vec![2]);
        assert!(selector_match_lines(src2, b2, "Bar").is_empty());
    }

    #[test]
    fn selector_skips_comments_and_word_fragments() {
        let src = "import 'package:c/c.dart';\n// Foo();\nxFoo();\nFoo2();\n";
        let b = &collect_dart_import_bindings(src)[0];
        assert!(selector_match_lines(src, b, "Foo").is_empty());
        assert!(selector_match_lines("x", b, "").is_empty());
    }
}
