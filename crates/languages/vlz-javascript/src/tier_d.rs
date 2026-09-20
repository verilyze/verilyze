// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! JavaScript Tier D: import-binding selector matching (FR-032).
//!
//! First-party only -- does not read `node_modules`. Heuristic regex, not a
//! full JS AST or dependency call graph.

use crate::reachability::package_name_from_specifier;

/// One import binding of a package into a local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsImportBinding {
    /// Local identifier used in source (`_`, `lodash`, `map`, …).
    pub local: String,
    /// Package name (`lodash`, `@scope/pkg`).
    pub package: String,
    /// True when this binding is a named import (`import { map } from …`).
    pub named: bool,
}

/// Trailing identifier of an advisory symbol (`lodash.get` -> `get`).
pub fn trailing_js_ident(symbol: &str) -> Option<&str> {
    let ident = symbol.rsplit(['.', '/', ':']).next().unwrap_or(symbol);
    if ident.is_empty() {
        return None;
    }
    let first = ident.chars().next()?;
    if !first.is_ascii_alphabetic() && first != '_' && first != '$' {
        return None;
    }
    if !ident
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    Some(ident)
}

/// Collect default, namespace, and named import bindings from source text.
pub fn collect_js_import_bindings(content: &str) -> Vec<JsImportBinding> {
    let mut out = Vec::new();
    // import name from 'pkg' / import * as name from 'pkg'
    let default_re = regex::Regex::new(
        r#"(?i)\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]"#,
    )
    .expect("js default import regex");
    for caps in default_re.captures_iter(content) {
        let local = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let spec = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if let Some(pkg) = package_name_from_specifier(spec)
            && !local.is_empty()
        {
            out.push(JsImportBinding {
                local: local.to_string(),
                package: pkg,
                named: false,
            });
        }
    }
    // import { a, b as c } from 'pkg'
    let named_re = regex::Regex::new(
        r#"(?i)\bimport\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]"#,
    )
    .expect("js named import regex");
    for caps in named_re.captures_iter(content) {
        let names = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let spec = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let Some(pkg) = package_name_from_specifier(spec) else {
            continue;
        };
        for part in names.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let local = if let Some((_, alias)) =
                part.split_once(" as ").or_else(|| part.split_once(" AS "))
            {
                alias.trim()
            } else {
                part.trim()
            };
            if local.is_empty()
                || !local.chars().next().is_some_and(|c| {
                    c.is_ascii_alphabetic() || c == '_' || c == '$'
                })
            {
                continue;
            }
            out.push(JsImportBinding {
                local: local.to_string(),
                package: pkg.clone(),
                named: true,
            });
        }
    }
    // const name = require('pkg')
    let require_re = regex::Regex::new(
        r#"(?i)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .expect("js require binding regex");
    for caps in require_re.captures_iter(content) {
        let local = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let spec = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if let Some(pkg) = package_name_from_specifier(spec)
            && !local.is_empty()
        {
            out.push(JsImportBinding {
                local: local.to_string(),
                package: pkg,
                named: false,
            });
        }
    }
    out
}

/// 1-based lines where `local.ident` appears outside line comments (heuristic).
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
                || !bytes[abs - 1].is_ascii_alphanumeric()
                    && bytes[abs - 1] != b'_'
                    && bytes[abs - 1] != b'$';
            let after = abs + needle_bytes.len();
            let after_ok = after >= bytes.len()
                || !bytes[after].is_ascii_alphanumeric()
                    && bytes[after] != b'_'
                    && bytes[after] != b'$';
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
    fn trailing_js_ident_from_qualified_symbol() {
        assert_eq!(trailing_js_ident("lodash.get"), Some("get"));
        assert_eq!(trailing_js_ident("get"), Some("get"));
        assert_eq!(trailing_js_ident(""), None);
        assert_eq!(trailing_js_ident("1bad"), None);
    }

    #[test]
    fn collect_default_and_named_imports() {
        let content = r#"
import _ from 'lodash';
import { map as mapFn, get } from 'lodash';
const chalk = require('chalk');
"#;
        let binds = collect_js_import_bindings(content);
        assert!(
            binds
                .iter()
                .any(|b| b.local == "_" && b.package == "lodash")
        );
        assert!(binds.iter().any(|b| b.local == "mapFn" && b.named));
        assert!(binds.iter().any(|b| b.local == "get" && b.named));
        assert!(
            binds
                .iter()
                .any(|b| b.local == "chalk" && b.package == "chalk")
        );
    }

    #[test]
    fn selector_match_finds_member_access() {
        let content = "const x = _.get(obj, 'a');\n// _.get(fake)\n";
        let lines = selector_match_lines(content, &["_".into()], "get");
        assert_eq!(lines, vec![1]);
    }
}
