// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ruby Tier D: require-binding selector matching (FR-032).
//!
//! First-party only. Heuristic regex, not a full Ruby AST or call graph.

/// One require binding into a constant-like local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyRequireBinding {
    /// Heuristic constant / receiver (`Rack`, `OpenSSL`, …).
    pub local: String,
    /// Required feature string (`rack`, `openssl`, …).
    pub feature: String,
}

/// Trailing identifier of an advisory symbol (`Rack::Request#get` -> `get`).
pub fn trailing_ruby_ident(symbol: &str) -> Option<&str> {
    let ident = symbol.rsplit(['#', ':', '.', '/']).next().unwrap_or(symbol);
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

fn camelize_feature(feature: &str) -> String {
    feature
        .split(['_', '-', '/'])
        .filter(|p| !p.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Collect require bindings from Ruby source text.
pub fn collect_ruby_require_bindings(
    content: &str,
) -> Vec<RubyRequireBinding> {
    let mut out = Vec::new();
    let re = regex::Regex::new(
        r#"(?:\brequire(?:_relative)?\s*(?:\(\s*)?|\bautoload\s+[^,]+,\s*)['"]([^'"]+)['"]"#,
    )
    .expect("ruby require binding regex");
    for caps in re.captures_iter(content) {
        let feature = caps
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .trim_start_matches("./")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        if feature.is_empty() {
            continue;
        }
        let local = camelize_feature(&feature);
        if local.is_empty() {
            continue;
        }
        out.push(RubyRequireBinding { local, feature });
    }
    out
}

/// True when a require feature matches a gem name.
pub fn binding_matches_package(
    binding: &RubyRequireBinding,
    package: &str,
) -> bool {
    let package_norm = package.replace('-', "_").to_ascii_lowercase();
    let feature_norm = binding.feature.replace('-', "_").to_ascii_lowercase();
    feature_norm == package_norm
        || feature_norm.replace('_', "") == package_norm.replace('_', "")
}

/// 1-based lines where `Local.ident` or `Local::ident` appear.
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
            vlz_reachability_trait::LineCommentStyle::Hash,
        );
        if locals.iter().any(|local| {
            contains_bounded(&code, &format!("{local}.{ident}"))
                || contains_bounded(&code, &format!("{local}::{ident}"))
        }) {
            lines.push((idx + 1) as u32);
        }
    }
    lines
}

fn contains_bounded(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while start + needle_bytes.len() <= bytes.len() {
        if let Some(rel) = line[start..].find(needle) {
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
    fn trailing_ruby_ident_and_require_bindings() {
        assert_eq!(trailing_ruby_ident("Rack::Request#get"), Some("get"));
        let content =
            "require 'rack'\nRack.get('/')".to_string() + "\n# Rack.get\n";
        let binds = collect_ruby_require_bindings(&content);
        assert!(
            binds
                .iter()
                .any(|b| b.feature == "rack" && b.local == "Rack")
        );
        assert!(binding_matches_package(&binds[0], "rack"));
        let lines = selector_match_lines(&content, &["Rack".into()], "get");
        assert_eq!(lines, vec![2]);
    }
}
