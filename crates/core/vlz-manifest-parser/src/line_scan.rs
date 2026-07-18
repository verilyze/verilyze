// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_db::Package;

/// Parsed lock stanza with line number of the stanza header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockStanza {
    pub package: Package,
    pub start_line: u32,
}

/// Scan TOML lock content for `[[header]]` stanzas with `name` and `version` keys.
pub fn scan_toml_lock_stanzas(
    content: &str,
    header: &str,
    ecosystem: &str,
) -> Vec<LockStanza> {
    let mut stanzas = Vec::new();
    let mut current_start: Option<u32> = None;
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    let flush = |stanzas: &mut Vec<LockStanza>,
                 start: Option<u32>,
                 name: Option<String>,
                 version: Option<String>,
                 ecosystem: &str| {
        if let (Some(line), Some(name)) = (start, name) {
            stanzas.push(LockStanza {
                package: Package {
                    name,
                    version: version.unwrap_or_else(|| "any".to_string()),
                    ecosystem: Some(ecosystem.to_string()),
                },
                start_line: line,
            });
        }
    };

    for (i, line) in content.lines().enumerate() {
        let line_no = (i + 1) as u32;
        let trimmed = line.trim();
        if trimmed == header {
            flush(
                &mut stanzas,
                current_start,
                current_name.take(),
                current_version.take(),
                ecosystem,
            );
            current_start = Some(line_no);
            continue;
        }
        if current_start.is_none() {
            continue;
        }
        if let Some((key, value)) = parse_toml_key_value(trimmed) {
            match key.as_str() {
                "name" => current_name = Some(value),
                "version" => current_version = Some(value),
                _ => {}
            }
        }
    }
    flush(
        &mut stanzas,
        current_start,
        current_name,
        current_version,
        ecosystem,
    );
    stanzas
}

fn parse_toml_key_value(line: &str) -> Option<(String, String)> {
    let (key, rest) = line.split_once('=')?;
    let key = key.trim().trim_matches('"').to_string();
    let value = rest.trim().trim_matches('"').trim_matches('\'').to_string();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Scan Cargo.toml-style `[section]` dependency keys.
pub fn scan_toml_section_deps(
    content: &str,
    sections: &[&str],
    ecosystem: &str,
) -> Vec<(u32, String, String)> {
    let mut out = Vec::new();
    let mut in_section = false;
    for (i, line) in content.lines().enumerate() {
        let line_no = (i + 1) as u32;
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_matches(['[', ']']);
            in_section = sections.contains(&section);
            continue;
        }
        if !in_section || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, version)) = parse_dep_key_line(trimmed) {
            out.push((line_no, name, version));
        }
    }
    let _ = ecosystem;
    out
}

fn parse_dep_key_line(line: &str) -> Option<(String, String)> {
    if line.starts_with('[') {
        return None;
    }
    if let Some((name, rest)) = line.split_once('=') {
        let name = name.trim().trim_matches('"').to_string();
        let rest = rest.trim();
        if rest.starts_with('{') {
            let version = extract_inline_version(rest);
            return Some((name, version));
        }
        let version = rest.trim_matches('"').trim().to_string();
        return Some((name, version));
    }
    None
}

fn extract_inline_version(table: &str) -> String {
    for part in table.split(',') {
        let part = part.trim().trim_matches(['{', '}']);
        if let Some((key, val)) = part.split_once('=')
            && key.trim() == "version"
        {
            return val.trim().trim_matches('"').to_string();
        }
    }
    if table.contains("path") || table.contains("git") {
        return "any".to_string();
    }
    "any".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_poetry_lock_stanzas() {
        let content = r#"
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "httpx"
version = "0.25.0"
"#;
        let stanzas = scan_toml_lock_stanzas(content, "[[package]]", "PyPI");
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[0].start_line, 2);
        assert_eq!(stanzas[0].package.name, "requests");
        assert_eq!(stanzas[0].package.version, "2.31.0");
    }

    #[test]
    fn scan_cargo_toml_deps() {
        let content = r#"
[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;
        let deps =
            scan_toml_section_deps(content, &["dependencies"], "crates.io");
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0], (3, "serde".to_string(), "1.0".to_string()));
    }
}
