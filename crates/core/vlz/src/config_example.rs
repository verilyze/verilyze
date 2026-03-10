// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Generate verilyze.conf.example content at runtime with effective values.
//! Descriptions are parsed from config-comments.yaml embedded at compile time.

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

use std::collections::HashMap;

const CONFIG_COMMENTS: &str =
    include_str!("../../../../scripts/config-comments.yaml");

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

/// Parse config-comments.yaml (simple subset) to extract key -> description.
fn parse_descriptions(yaml: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut current_key: Option<String> = None;

    for line in yaml.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("  ") {
            if let Some(key) = &current_key
                && let Some(rest) = trimmed.strip_prefix("  description:")
            {
                let val = rest
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !val.is_empty() {
                    result.insert(key.clone(), val);
                }
            }
        } else if let Some(idx) = trimmed.find(':') {
            let key = trimmed[..idx].trim();
            if !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
            {
                current_key = Some(key.to_string());
            }
        }
    }
    result
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
        ("cache_ttl_secs", cfg.cache_ttl_secs.to_string()),
        ("min_score", cfg.min_score.to_string()),
        ("min_count", cfg.min_count.to_string()),
        (
            "exit_code_on_cve",
            cfg.exit_code_on_cve.unwrap_or(86).to_string(),
        ),
        ("fp_exit_code", cfg.fp_exit_code.unwrap_or(0).to_string()),
        ("backoff_base_ms", cfg.backoff_base_ms.to_string()),
        ("backoff_max_ms", cfg.backoff_max_ms.to_string()),
        ("max_retries", cfg.max_retries.to_string()),
    ];

    for (key, value) in scalar_entries {
        let desc = descriptions.get(key).map(|s| s.as_str()).unwrap_or("");
        for comment_line in wrap_comment(desc, LINE_LENGTH) {
            lines.push(comment_line);
        }
        let val_display = if key == "cache_db" || key == "ignore_db" {
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
            let val = match (v, t) {
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
            };
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
    use std::path::PathBuf;

    fn minimal_config() -> crate::config::EffectiveConfig {
        crate::config::EffectiveConfig {
            cache_db: Some(PathBuf::from("/tmp/cache.redb")),
            ignore_db: Some(PathBuf::from("/tmp/ignore.redb")),
            parallel_queries: 10,
            cache_ttl_secs: 432000,
            min_score: 0.0,
            min_count: 0,
            exit_code_on_cve: Some(86),
            fp_exit_code: Some(0),
            backoff_base_ms: 100,
            backoff_max_ms: 30_000,
            max_retries: 5,
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
}
