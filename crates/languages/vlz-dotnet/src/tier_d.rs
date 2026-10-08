// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! .NET Tier D: using-binding selector matching (FR-032).
//!
//! First-party only. Heuristic regex, not a full C# / F# AST or call graph.

/// One `using` / `open` binding into a namespace or type local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetUsingBinding {
    /// Last segment of the using path (`Json`, `Linq`, …).
    pub local: String,
    /// Full using / open path.
    pub path: String,
}

/// Trailing identifier of an advisory symbol (`JsonConvert.Serialize` -> `Serialize`).
pub fn trailing_dotnet_ident(symbol: &str) -> Option<&str> {
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

/// Collect using/open bindings from C# / F# source text.
pub fn collect_dotnet_using_bindings(
    content: &str,
) -> Vec<DotnetUsingBinding> {
    let mut out = Vec::new();
    let re = regex::Regex::new(
        r#"(?x)
        (?:
          \busing\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*;
          |
          \bopen\s+([A-Za-z_][A-Za-z0-9_.]*)
        )"#,
    )
    .expect("dotnet using binding regex");
    for caps in re.captures_iter(content) {
        let path = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if path.is_empty() {
            continue;
        }
        let local = path.rsplit('.').next().unwrap_or(path);
        if local.is_empty() {
            continue;
        }
        out.push(DotnetUsingBinding {
            local: local.to_string(),
            path: path.to_string(),
        });
    }
    out
}

/// True when a using path matches a NuGet package name.
pub fn binding_matches_package(
    binding: &DotnetUsingBinding,
    package: &str,
) -> bool {
    let pkg_lower = package.to_ascii_lowercase();
    let path_lower = binding.path.to_ascii_lowercase();
    let pkg_compact = pkg_lower.replace(['.', '-', '_'], "");
    let path_compact = path_lower.replace(['.', '-', '_'], "");
    path_lower.contains(&pkg_lower)
        || pkg_lower.contains(&path_lower)
        || path_compact.contains(&pkg_compact)
        || (pkg_lower.len() >= 3
            && path_lower
                .split('.')
                .any(|seg| pkg_lower.split('.').any(|p| p == seg)))
}

/// Receiver prefix of an advisory symbol (`JsonConvert.Serialize` -> `JsonConvert`).
pub fn symbol_receiver(symbol: &str) -> Option<&str> {
    let (head, _) = symbol.rsplit_once('.')?;
    if head.is_empty() || head.contains('/') {
        return None;
    }
    let last = head.rsplit('.').next()?;
    if last.is_empty() { None } else { Some(last) }
}

/// 1-based lines where `Receiver.ident` appears for package-related usings.
pub fn selector_match_lines(
    content: &str,
    receivers: &[String],
    ident: &str,
) -> Vec<u32> {
    if receivers.is_empty() || ident.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let code = vlz_reachability_trait::line_code_for_symbol_match(
            line.trim(),
            vlz_reachability_trait::LineCommentStyle::SlashSlash,
        );
        if receivers
            .iter()
            .any(|recv| contains_bounded(&code, &format!("{recv}.{ident}")))
        {
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
    fn trailing_dotnet_ident_and_using_bindings() {
        assert_eq!(
            trailing_dotnet_ident("JsonConvert.SerializeObject"),
            Some("SerializeObject")
        );
        assert_eq!(
            symbol_receiver("JsonConvert.SerializeObject"),
            Some("JsonConvert")
        );
        let content = "using Newtonsoft.Json;\nJsonConvert.SerializeObject(x);\n\
             // JsonConvert.SerializeObject\n";
        let binds = collect_dotnet_using_bindings(content);
        assert!(binds.iter().any(|b| b.path.contains("Newtonsoft")));
        assert!(binding_matches_package(
            binds
                .iter()
                .find(|b| b.path.contains("Newtonsoft"))
                .unwrap(),
            "Newtonsoft.Json"
        ));
        let lines = selector_match_lines(
            content,
            &["JsonConvert".into()],
            "SerializeObject",
        );
        assert_eq!(lines, vec![2]);
    }
}
