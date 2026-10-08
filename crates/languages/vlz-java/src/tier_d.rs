// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Java/Kotlin Tier D: import-binding selector matching (FR-032).
//!
//! First-party only. Heuristic regex, not a full Java AST or call graph.

use crate::reachability::{import_matches_package, normalize_import_path};

/// One import binding of a package type into a local simple name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaImportBinding {
    /// Local identifier (`Lists`, `Widget`, …).
    pub local: String,
    /// Full import path (`com.google.common.collect.Lists`).
    pub import_path: String,
}

/// Trailing identifier of an advisory symbol (`com.example.Lib.vuln` -> `vuln`).
pub fn trailing_java_ident(symbol: &str) -> Option<&str> {
    let ident = symbol.rsplit(['.', '/', ':']).next().unwrap_or(symbol);
    if ident.is_empty() {
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

/// Collect import bindings from Java/Kotlin source text.
pub fn collect_java_import_bindings(content: &str) -> Vec<JavaImportBinding> {
    let mut out = Vec::new();
    for line in content.lines() {
        let code = vlz_reachability_trait::line_code_for_symbol_match(
            line.trim(),
            vlz_reachability_trait::LineCommentStyle::SlashSlash,
        );
        let rest = code
            .strip_prefix("import static ")
            .or_else(|| code.strip_prefix("import "))
            .unwrap_or("");
        let Some(path) = normalize_import_path(rest) else {
            continue;
        };
        let Some(local) = path.rsplit('.').next() else {
            continue;
        };
        if local.is_empty() || local == "*" {
            continue;
        }
        out.push(JavaImportBinding {
            local: local.to_string(),
            import_path: path,
        });
    }
    out
}

/// True when an import path is evidence for this Maven `group:artifact`.
pub fn binding_matches_package(
    binding: &JavaImportBinding,
    name: &str,
) -> bool {
    import_matches_package(&binding.import_path, name)
}

/// 1-based lines where `local.ident` appears outside line comments.
pub fn selector_match_lines(
    content: &str,
    locals: &[String],
    ident: &str,
) -> Vec<u32> {
    if locals.is_empty() || ident.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let code = vlz_reachability_trait::line_code_for_symbol_match(
            line.trim(),
            vlz_reachability_trait::LineCommentStyle::SlashSlash,
        );
        if locals
            .iter()
            .any(|local| line_has_selector(&code, local, ident))
        {
            lines.push((idx + 1) as u32);
        }
    }
    lines
}

fn line_has_selector(line: &str, local: &str, ident: &str) -> bool {
    let needle = format!("{local}.{ident}");
    let bytes = line.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while start + needle_bytes.len() <= bytes.len() {
        if let Some(rel) = line[start..].find(&needle) {
            let abs = start + rel;
            let before_ok = abs == 0
                || (!bytes[abs - 1].is_ascii_alphanumeric()
                    && bytes[abs - 1] != b'_');
            let after = abs + needle_bytes.len();
            let after_ok = after >= bytes.len()
                || (!bytes[after].is_ascii_alphanumeric()
                    && bytes[after] != b'_');
            if before_ok && after_ok {
                return true;
            }
            start = abs + 1;
        } else {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_java_ident_from_qualified_symbol() {
        assert_eq!(
            trailing_java_ident("com.example.Lib.vulnerable"),
            Some("vulnerable")
        );
        assert_eq!(trailing_java_ident("vulnerable"), Some("vulnerable"));
        assert_eq!(trailing_java_ident(""), None);
        assert_eq!(trailing_java_ident("1bad"), None);
    }

    #[test]
    fn collect_imports_and_selector_match() {
        let content = "import com.example.widget.Widget;\n\
             class App { void m() { Widget.vulnerable(); } }\n\
             // Widget.vulnerable()\n";
        let binds = collect_java_import_bindings(content);
        assert!(binds.iter().any(|b| {
            b.local == "Widget" && b.import_path == "com.example.widget.Widget"
        }));
        assert!(binding_matches_package(
            &binds[0],
            "com.example.widget:widget"
        ));
        let lines =
            selector_match_lines(content, &["Widget".into()], "vulnerable");
        assert_eq!(lines, vec![2]);
    }
}
