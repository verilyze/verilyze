// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Generate verilyze.conf.example content at runtime with effective values.
//! Descriptions are parsed from config-comments.toml embedded at compile time.

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

use std::collections::HashMap;

const CONFIG_COMMENTS: &str =
    include_str!("../../../../scripts/config-comments.toml");

/// Wrap text into comment lines, each prefixed with "# " and at most `width` chars.
/// Returns empty vec for empty or whitespace-only text.
pub(crate) fn wrap_comment(text: &str, width: usize) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    let prefix = "# ";
    let content_width = width.saturating_sub(prefix.len());
    let mut result = Vec::new();
    let mut remaining = trimmed;
    while !remaining.is_empty() {
        let (line, rest) = if remaining.len() <= content_width {
            (remaining.to_string(), "")
        } else {
            let mut break_at = content_width.min(remaining.len());
            let slice = &remaining[..break_at];
            if let Some(last_space) = slice.rfind(char::is_whitespace) {
                break_at = last_space;
            }
            let (line, rest) = remaining.split_at(break_at);
            (line.trim_end().to_string(), rest.trim_start())
        };
        if !line.is_empty() {
            result.push(format!("{}{}", prefix, line));
        }
        remaining = rest;
    }
    result
}

/// Parse config-comments.toml to extract key -> description.
fn parse_descriptions(raw: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let Ok(mapping) = toml::from_str::<toml::Table>(raw) else {
        return result;
    };
    for (key, v) in mapping {
        let Some(nested) = v.as_table() else {
            continue;
        };
        let Some(desc_val) = nested.get("description") else {
            continue;
        };
        let Some(text) = desc_val.as_str() else {
            continue;
        };
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if !text.is_empty() {
            result.insert(key.clone(), text);
        }
    }
    result
}

/// Look up a severity threshold for example output. Unknown `version` / `field` return `0.0`
/// so the default match arm stays testable and documented.
fn severity_threshold_for_example(
    cfg: &crate::config::EffectiveConfig,
    version: &str,
    field: &str,
) -> f32 {
    match (version, field) {
        ("v2", "critical_min") => cfg.severity.v2.critical_min,
        ("v2", "high_min") => cfg.severity.v2.high_min,
        ("v2", "medium_min") => cfg.severity.v2.medium_min,
        ("v2", "low_min") => cfg.severity.v2.low_min,
        ("v3", "critical_min") => cfg.severity.v3.critical_min,
        ("v3", "high_min") => cfg.severity.v3.high_min,
        ("v3", "medium_min") => cfg.severity.v3.medium_min,
        ("v3", "low_min") => cfg.severity.v3.low_min,
        ("v4", "critical_min") => cfg.severity.v4.critical_min,
        ("v4", "high_min") => cfg.severity.v4.high_min,
        ("v4", "medium_min") => cfg.severity.v4.medium_min,
        ("v4", "low_min") => cfg.severity.v4.low_min,
        _ => 0.0,
    }
}

/// Generate verilyze.conf.example content with effective config values.
pub fn generate_example(cfg: &crate::config::EffectiveConfig) -> String {
    let descriptions = parse_descriptions(CONFIG_COMMENTS);

    let cache_db = cfg
        .cache_db
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            crate::config::default_cache_path().display().to_string()
        });
    let ignore_db = cfg
        .ignore_db
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            crate::config::default_ignore_path().display().to_string()
        });

    // REUSE-IgnoreStart -- example output content, not file header
    let mut lines: Vec<String> = vec![
        "# verilyze(1) configuration file".to_string(),
        "# Copy to ~/.config/verilyze/verilyze.conf or /etc/verilyze.conf"
            .to_string(),
        "# Precedence: CLI > env (VLZ_*) > user config > system config"
            .to_string(),
        "#".to_string(),
    ];

    let scalar_entries: Vec<(&str, String)> = vec![
        ("cache_db", cache_db),
        ("ignore_db", ignore_db),
        ("parallel_queries", cfg.parallel_queries.to_string()),
        ("scan_exclude_dirs", cfg.scan_exclude_dirs.join(",")),
        ("cache_ttl_secs", cfg.cache_ttl_secs.to_string()),
        ("min_score", cfg.min_score.to_string()),
        ("min_count", cfg.min_count.to_string()),
        (
            "exit_code_on_cve",
            cfg.exit_code_on_cve.unwrap_or(86).to_string(),
        ),
        ("fp_exit_code", cfg.fp_exit_code.unwrap_or(0).to_string()),
        (
            "project_id",
            cfg.project_id.as_deref().unwrap_or("").to_string(),
        ),
        ("backoff_base_ms", cfg.backoff_base_ms.to_string()),
        ("backoff_max_ms", cfg.backoff_max_ms.to_string()),
        ("max_retries", cfg.max_retries.to_string()),
        (
            "provider_http_connect_timeout_secs",
            cfg.provider_http_connect_timeout_secs.to_string(),
        ),
        (
            "provider_http_request_timeout_secs",
            cfg.provider_http_request_timeout_secs.to_string(),
        ),
        (
            "tls_crl_bundle",
            cfg.tls_crl_bundle
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ),
    ];

    for (key, value) in scalar_entries {
        let desc = descriptions.get(key).map(|s| s.as_str()).unwrap_or("");
        for comment_line in wrap_comment(desc, LINE_LENGTH) {
            lines.push(comment_line);
        }
        let val_display = if key == "cache_db"
            || key == "ignore_db"
            || key == "scan_exclude_dirs"
            || key == "tls_crl_bundle"
        {
            format!("\"{}\"", value)
        } else {
            value
        };
        lines.push(format!("# {} = {}", key, val_display));
        lines.push("".to_string());
    }

    lines.push("#".to_string());
    lines.push(
        "# [severity.v2], [severity.v3], [severity.v4] (CVSS thresholds)"
            .to_string(),
    );
    for v in ["v2", "v3", "v4"] {
        lines.push(format!("# [severity.{}]", v));
        for t in ["critical_min", "high_min", "medium_min", "low_min"] {
            let _key = format!("severity_{}_{}", v, t);
            let val = severity_threshold_for_example(cfg, v, t);
            lines.push(format!("# {} = {}", t, val));
        }
        lines.push("#".to_string());
    }

    lines.push("# Per-language manifest regex (FR-006)".to_string());
    for (lang, re) in &cfg.language_regexes {
        lines.push(format!("# [{}]", lang));
        lines.push(format!("# regex = \"{}\"", re));
        lines.push("".to_string());
    }

    // REUSE-IgnoreEnd
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS,
        DEFAULT_CACHE_TTL_SECS, DEFAULT_MAX_RETRIES, DEFAULT_PARALLEL_QUERIES,
    };
    use std::path::PathBuf;

    #[test]
    fn embedded_config_comments_toml_parses() {
        toml::from_str::<toml::Table>(CONFIG_COMMENTS).expect(
            "config-comments.toml embedded at compile time must parse",
        );
    }

    fn minimal_config() -> crate::config::EffectiveConfig {
        crate::config::EffectiveConfig {
            cache_db: Some(PathBuf::from("/tmp/cache.redb")),
            ignore_db: Some(PathBuf::from("/tmp/ignore.redb")),
            parallel_queries: DEFAULT_PARALLEL_QUERIES,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            min_score: 0.0,
            min_count: 0,
            exit_code_on_cve: Some(86),
            fp_exit_code: Some(0),
            backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
            backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
            max_retries: DEFAULT_MAX_RETRIES,
            language_regexes: vec![
                ("python".to_string(), "^requirements\\.txt$".to_string()),
                ("rust".to_string(), "^Cargo\\.toml$".to_string()),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn output_has_no_spdx() {
        let cfg = minimal_config();
        let out = generate_example(&cfg);
        assert!(
            !out.contains("SPDX-FileCopyrightText"),
            "machine-generated output should not contain SPDX"
        );
        assert!(
            !out.contains("SPDX-License-Identifier"),
            "machine-generated output should not contain SPDX"
        );
    }

    #[test]
    fn comment_above_value_not_inline() {
        let cfg = minimal_config();
        let out = generate_example(&cfg);
        assert!(
            out.contains("# parallel_queries = 10"),
            "should have value line"
        );
        assert!(
            !out.contains("  # Max concurrent"),
            "comment should not be inline with value"
        );
        assert!(
            out.contains("# Max concurrent CVE queries"),
            "comment should appear above value"
        );
    }

    #[test]
    fn line_length_matches_pyproject() {
        assert_eq!(
            super::LINE_LENGTH,
            79,
            "LINE_LENGTH must match pyproject.toml [tool.verilyze] line-length"
        );
    }

    #[test]
    fn all_lines_at_most_line_length_chars() {
        let cfg = minimal_config();
        let out = generate_example(&cfg);
        for line in out.lines() {
            assert!(
                line.len() <= super::LINE_LENGTH,
                "line exceeds {} chars: {:?}",
                super::LINE_LENGTH,
                line
            );
        }
    }

    #[test]
    fn wrap_comment_short_stays_single_line() {
        let result = super::wrap_comment("Short", super::LINE_LENGTH);
        assert_eq!(result, vec!["# Short"]);
    }

    #[test]
    fn wrap_comment_empty_returns_empty() {
        let result = super::wrap_comment("", super::LINE_LENGTH);
        assert!(result.is_empty());
    }

    #[test]
    fn wrap_comment_wraps_long_text() {
        let text = "Minimum count of CVEs meeting min-score to trigger exit code (0 = any) and more words to exceed one line";
        let result = super::wrap_comment(text, super::LINE_LENGTH);
        assert!(
            result.len() >= 2,
            "long text should wrap into multiple lines"
        );
        for line in result.iter() {
            assert!(
                line.len() <= super::LINE_LENGTH,
                "line {:?} exceeds {} chars",
                line,
                super::LINE_LENGTH
            );
            assert!(line.starts_with("# "));
        }
    }

    #[test]
    fn parse_descriptions_multiline_string() {
        let toml = r#"
[cache_db]
description = """
Path to CVE cache database (default: XDG_CACHE_HOME or
/var/cache)
"""
type = "string"
"#;
        let map = super::parse_descriptions(toml);
        let desc = map.get("cache_db").expect("cache_db key");
        assert!(
            desc.contains("Path to CVE cache database"),
            "unexpected description: {desc:?}"
        );
        assert!(
            desc.contains("XDG_CACHE_HOME"),
            "unexpected description: {desc:?}"
        );
        assert!(
            desc.contains("/var/cache"),
            "unexpected description: {desc:?}"
        );
    }

    #[test]
    fn parse_descriptions_invalid_toml_returns_empty() {
        let map = super::parse_descriptions("not toml {{{");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_descriptions_skips_non_table_top_level_value() {
        let raw = r#"
plain = "not a table"
[cache_db]
description = "ok"
"#;
        let map = super::parse_descriptions(raw);
        assert!(!map.contains_key("plain"));
        assert_eq!(map.get("cache_db").map(String::as_str), Some("ok"));
    }

    #[test]
    fn parse_descriptions_skips_table_without_description() {
        let raw = r#"
[cache_db]
type = "string"
"#;
        let map = super::parse_descriptions(raw);
        assert!(!map.contains_key("cache_db"));
    }

    #[test]
    fn parse_descriptions_skips_non_string_description() {
        let raw = r#"
[cache_db]
description = 42
"#;
        let map = super::parse_descriptions(raw);
        assert!(!map.contains_key("cache_db"));
    }

    #[test]
    fn parse_descriptions_skips_whitespace_only_description() {
        let raw = r#"
[cache_db]
description = "   \n  "
"#;
        let map = super::parse_descriptions(raw);
        assert!(!map.contains_key("cache_db"));
    }

    #[test]
    fn wrap_comment_whitespace_only_returns_empty() {
        let result = super::wrap_comment("   \t", super::LINE_LENGTH);
        assert!(result.is_empty());
    }

    #[test]
    fn wrap_comment_long_token_without_spaces_splits_at_width() {
        let width = 14;
        let token = "a".repeat(30);
        let result = super::wrap_comment(&token, width);
        assert!(
            result.len() >= 3,
            "expected multiple lines for long token, got {:?}",
            result
        );
        for line in &result {
            assert!(
                line.len() <= width,
                "line {:?} exceeds width {}",
                line,
                width
            );
            assert!(line.starts_with("# "));
        }
        let joined: String = result
            .iter()
            .map(|l| l.strip_prefix("# ").unwrap_or(l.as_str()))
            .collect::<String>();
        assert_eq!(joined, token);
    }

    fn example_config_default_paths() -> crate::config::EffectiveConfig {
        crate::config::EffectiveConfig {
            cache_db: None,
            ignore_db: None,
            parallel_queries: DEFAULT_PARALLEL_QUERIES,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            min_score: 0.0,
            min_count: 0,
            exit_code_on_cve: None,
            fp_exit_code: None,
            project_id: None,
            tls_crl_bundle: None,
            language_regexes: vec![],
            backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
            backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
            max_retries: DEFAULT_MAX_RETRIES,
            ..Default::default()
        }
    }

    #[test]
    fn generate_example_uses_default_paths_when_db_options_none() {
        let cfg = example_config_default_paths();
        let out = generate_example(&cfg);
        let cache_line = format!(
            "# cache_db = \"{}\"",
            crate::config::default_cache_path().display()
        );
        let ignore_line = format!(
            "# ignore_db = \"{}\"",
            crate::config::default_ignore_path().display()
        );
        assert!(
            out.contains(&cache_line),
            "expected default cache path line in output"
        );
        assert!(
            out.contains(&ignore_line),
            "expected default ignore path line in output"
        );
    }

    #[test]
    fn generate_example_optional_scalars_use_defaults_when_none() {
        let cfg = example_config_default_paths();
        let out = generate_example(&cfg);
        assert!(out.contains("# exit_code_on_cve = 86"));
        assert!(out.contains("# fp_exit_code = 0"));
        assert!(out.contains("# project_id = "));
    }

    #[test]
    fn generate_example_tls_crl_bundle_none_shows_quoted_empty() {
        let cfg = example_config_default_paths();
        let out = generate_example(&cfg);
        assert!(out.contains("# tls_crl_bundle = \"\""));
    }

    #[test]
    fn generate_example_tls_crl_bundle_some_shows_quoted_path() {
        let mut cfg = example_config_default_paths();
        cfg.tls_crl_bundle = Some(PathBuf::from("/tmp/crl.pem"));
        let out = generate_example(&cfg);
        assert!(out.contains("# tls_crl_bundle = \"/tmp/crl.pem\""));
    }

    #[test]
    fn generate_example_empty_language_regexes_omits_language_sections() {
        let cfg = example_config_default_paths();
        let out = generate_example(&cfg);
        assert!(out.contains("# Per-language manifest regex (FR-006)"));
        assert!(
            !out.contains("\n# [python]\n"),
            "unexpected language block when language_regexes is empty"
        );
    }

    #[test]
    fn severity_threshold_for_example_known_keys_match_config() {
        let cfg = minimal_config();
        assert_eq!(
            super::severity_threshold_for_example(&cfg, "v2", "critical_min"),
            cfg.severity.v2.critical_min
        );
        assert_eq!(
            super::severity_threshold_for_example(&cfg, "v4", "low_min"),
            cfg.severity.v4.low_min
        );
    }

    #[test]
    fn severity_threshold_for_example_unknown_version_or_field_returns_zero() {
        let cfg = minimal_config();
        assert_eq!(
            super::severity_threshold_for_example(&cfg, "v9", "critical_min"),
            0.0
        );
        assert_eq!(
            super::severity_threshold_for_example(&cfg, "v2", "not_a_field"),
            0.0
        );
        assert_eq!(
            super::severity_threshold_for_example(&cfg, "vx", "high_min"),
            0.0
        );
    }

    #[test]
    fn wrap_comment_last_segment_fits_without_extra_break() {
        let width = 12;
        let prefix = "# ";
        let content_width = width - prefix.len();
        let tail = "end";
        let text = format!("{} {}", "a".repeat(content_width), tail);
        let result = super::wrap_comment(&text, width);
        assert!(
            result
                .iter()
                .any(|l| l
                    == &format!("{}{}", prefix, "a".repeat(content_width))),
            "expected full-width chunk, got {:?}",
            result
        );
        assert!(result.iter().any(|l| l == &format!("{}{}", prefix, tail)));
    }

    #[test]
    fn generate_example_project_id_some_is_unquoted_in_value_line() {
        let mut cfg = example_config_default_paths();
        cfg.project_id = Some("my-project".to_string());
        let out = generate_example(&cfg);
        assert!(out.contains("# project_id = my-project"));
    }

    #[test]
    fn generate_example_single_language_regex_section() {
        let mut cfg = example_config_default_paths();
        cfg.language_regexes =
            vec![("go".to_string(), "^go\\.mod$".to_string())];
        let out = generate_example(&cfg);
        assert!(out.contains("\n# [go]\n"));
        assert!(out.contains(r#"# regex = "^go\.mod$""#));
    }
}
