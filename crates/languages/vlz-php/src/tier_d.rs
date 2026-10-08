// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! PHP Tier D: use-binding selector matching (FR-032).
//!
//! First-party only. Heuristic regex, not a full PHP AST or call graph.

/// One `use` binding of a package into a local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpUseBinding {
    /// Local identifier (`Request`, `Logger`, alias, …).
    pub local: String,
    /// Fully-qualified use path with backslashes.
    pub fqcn: String,
}

/// Trailing identifier of an advisory symbol (`Vendor\\Cls::method` -> `method`).
pub fn trailing_php_ident(symbol: &str) -> Option<&str> {
    let ident = symbol
        .rsplit([':', '\\', '.', '/'])
        .next()
        .unwrap_or(symbol);
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

/// Collect `use` bindings from PHP source text.
pub fn collect_php_use_bindings(content: &str) -> Vec<PhpUseBinding> {
    let mut out = Vec::new();
    let re = regex::Regex::new(
        r#"(?i)\buse\s+(?:function\s+|const\s+)?([A-Za-z_\\][A-Za-z0-9_\\]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;"#,
    )
    .expect("php use binding regex");
    for line in content.lines() {
        let code = vlz_reachability_trait::line_code_for_symbol_match(
            line.trim(),
            vlz_reachability_trait::LineCommentStyle::SlashSlash,
        );
        for caps in re.captures_iter(&code) {
            let fqcn = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if fqcn.is_empty() {
                continue;
            }
            let local = if let Some(alias) = caps.get(2) {
                alias.as_str().to_string()
            } else {
                fqcn.rsplit('\\').next().unwrap_or(fqcn).to_string()
            };
            if local.is_empty() {
                continue;
            }
            out.push(PhpUseBinding {
                local,
                fqcn: fqcn.to_string(),
            });
        }
    }
    out
}

/// True when a use path matches Packagist `vendor/name`.
///
/// Matches full `vendor/name` compaction, vendor+name presence, or (when the
/// package name is long enough) the name alone -- PSR-4 roots like
/// `nesbot/carbon` -> `Carbon\Carbon` omit the vendor segment.
pub fn binding_matches_package(
    binding: &PhpUseBinding,
    package: &str,
) -> bool {
    let lower = package.to_ascii_lowercase();
    let Some((vendor, name)) = lower.split_once('/') else {
        return false;
    };
    if vendor.len() < 2 || name.len() < 2 {
        return false;
    }
    let fq = binding.fqcn.to_ascii_lowercase().replace('\\', "/");
    let compact_pkg = lower.replace(['/', '-', '_'], "");
    let compact_fq = fq.replace(['/', '-', '_'], "");
    let name_compact = name.replace(['-', '_'], "");
    if compact_fq.contains(&compact_pkg) {
        return true;
    }
    if fq.contains(vendor)
        && (fq.contains(name) || compact_fq.contains(&name_compact))
    {
        return true;
    }
    name_compact.len() >= 4
        && (fq.contains(name) || compact_fq.contains(&name_compact))
}

/// 1-based lines where `$local->ident`, `local::ident`, or `local.ident` appear.
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
        if locals.iter().any(|local| {
            line_has_selector(&code, local, ident)
                || line_has_static_selector(&code, local, ident)
        }) {
            lines.push((idx + 1) as u32);
        }
    }
    lines
}

fn line_has_selector(line: &str, local: &str, ident: &str) -> bool {
    let needle = format!("${local}->{ident}");
    contains_bounded(line, &needle)
}

fn line_has_static_selector(line: &str, local: &str, ident: &str) -> bool {
    contains_bounded(line, &format!("{local}::{ident}"))
        || contains_bounded(line, &format!("{local}.{ident}"))
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
                    && bytes[abs - 1] != b'_'
                    && bytes[abs - 1] != b'$');
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
    fn trailing_php_ident_and_use_bindings() {
        assert_eq!(
            trailing_php_ident("Monolog\\Logger::warning"),
            Some("warning")
        );
        let content =
            "<?php\nuse Monolog\\Logger as Log;\nLog::warning('x');\n";
        let binds = collect_php_use_bindings(content);
        assert!(
            binds
                .iter()
                .any(|b| b.local == "Log" && b.fqcn.contains("Monolog"))
        );
        assert!(binding_matches_package(&binds[0], "monolog/monolog"));
        let lines = selector_match_lines(content, &["Log".into()], "warning");
        assert_eq!(lines, vec![3]);
    }

    #[test]
    fn binding_matches_package_without_vendor_in_fqcn() {
        let carbon = PhpUseBinding {
            local: "Carbon".into(),
            fqcn: "Carbon\\Carbon".into(),
        };
        assert!(binding_matches_package(&carbon, "nesbot/carbon"));
        let commented = collect_php_use_bindings(
            "<?php\n// use Evil\\Pkg;\nuse Carbon\\Carbon;\n",
        );
        assert_eq!(commented.len(), 1);
        assert_eq!(commented[0].fqcn, "Carbon\\Carbon");
    }

    #[test]
    fn php_tier_d_edge_cases() {
        assert_eq!(trailing_php_ident("Foo\\"), None);
        assert_eq!(trailing_php_ident("1bad"), None);
        assert_eq!(trailing_php_ident("bad-name"), None);
        assert!(!binding_matches_package(
            &PhpUseBinding {
                local: "X".into(),
                fqcn: "X".into(),
            },
            "noslash"
        ));
        assert!(!binding_matches_package(
            &PhpUseBinding {
                local: "X".into(),
                fqcn: "X".into(),
            },
            "a/b"
        ));
        assert!(selector_match_lines("x", &[], "warning").is_empty());
        assert!(selector_match_lines("x", &["Log".into()], "").is_empty());
        let content =
            "<?php\n$xLog->warning\n$Log->warning('x');\nLog::warning('y');\n";
        assert_eq!(
            selector_match_lines(content, &["Log".into()], "warning"),
            vec![3, 4]
        );
        let function_use =
            collect_php_use_bindings("<?php\nuse function Foo\\bar;\n");
        assert!(function_use.iter().any(|b| b.fqcn.contains("Foo")));
    }
}
