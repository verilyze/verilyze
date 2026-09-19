// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared CLI enumerated values and clap `value_parser` builders for shell completion.

use clap::builder::PossibleValuesParser;

/// Output formats for `vlz scan --format` (stdout reporter).
pub const SCAN_OUTPUT_FORMATS: &[&str] =
    &["plain", "json", "sarif", "cyclonedx", "spdx", "openvex"];

/// Output formats for `vlz fix --dry-run --format`.
pub const FIX_OUTPUT_FORMATS: &[&str] = &["plain", "json"];

/// Output formats for `vlz db show --format`.
pub const DB_SHOW_FORMATS: &[&str] = &["json"];

/// Deprecated CLI aliases: accepted at runtime and in `--help`, omitted from
/// shell completions so TAB suggests preferred names only.
pub const COMPLETION_OMIT_ALIASES: &[&str] = &[
    "list",             // languages
    "summary-file",     // --report
    "exit-code-on-cve", // --exit-code
];

#[cfg(not(feature = "completions"))]
const HELP_SUBCOMMANDS_BASE: &[&str] = &[
    "scan",
    "fix",
    "languages",
    "list",
    "config",
    "db",
    "fp",
    "preload",
    "help",
];

/// Mock CVE provider names registered only for integration tests.
#[cfg(any(test, feature = "testing"))]
pub const TESTING_PROVIDER_NAMES: &[&str] = &[
    "failing",
    "counting",
    "cve_returning",
    "panicking",
    "tier_c_reachability",
    "low_score",
];

/// Production CVE provider names for the current build (feature-gated).
pub fn production_provider_names() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names = vec![crate::config::DEFAULT_CVE_PROVIDER];
    #[cfg(feature = "nvd")]
    names.push("nvd");
    #[cfg(feature = "github")]
    names.push("github");
    #[cfg(feature = "sonatype")]
    names.push("sonatype");
    names
}

/// Registered CVE provider names for the current build (feature-gated).
pub fn provider_names() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names = production_provider_names();
    #[cfg(any(test, feature = "testing"))]
    names.extend_from_slice(TESTING_PROVIDER_NAMES);
    names
}

/// Top-level subcommand names for `vlz help [SUBCOMMAND]`.
pub fn help_subcommand_names() -> &'static [&'static str] {
    #[cfg(feature = "completions")]
    {
        const WITH_COMPLETIONS: &[&str] = &[
            "scan",
            "fix",
            "languages",
            "list",
            "config",
            "db",
            "fp",
            "preload",
            "help",
            "generate-completions",
        ];
        WITH_COMPLETIONS
    }
    #[cfg(not(feature = "completions"))]
    {
        HELP_SUBCOMMANDS_BASE
    }
}

/// `value_parser` for `scan --format`.
pub fn scan_format_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(SCAN_OUTPUT_FORMATS)
}

/// `value_parser` for `fix --dry-run --format`.
pub fn fix_format_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(FIX_OUTPUT_FORMATS)
}

/// `value_parser` for `db show --format`.
pub fn db_show_format_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(DB_SHOW_FORMATS)
}

/// `value_parser` for `scan --provider` and `preload --provider`.
pub fn provider_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(provider_names())
}

/// Parse `--providers` CSV: registered names and/or `all`.
pub fn parse_providers_list_arg(value: &str) -> Result<String, String> {
    let tokens: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return Err(
            "providers list is empty (use `vlz db list-providers` to list)"
                .to_string(),
        );
    }
    let allowed = provider_names();
    for token in tokens {
        if token.eq_ignore_ascii_case("all") {
            continue;
        }
        if !allowed.iter().any(|n| n.eq_ignore_ascii_case(token)) {
            return Err(format!(
                "Unknown provider: {token} (use `vlz db list-providers` to list)"
            ));
        }
    }
    Ok(value.to_string())
}

/// `value_parser` for `help [SUBCOMMAND]`.
pub fn help_subcommand_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(help_subcommand_names())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command};

    fn parse_scan_format(value: &str) -> Result<String, clap::Error> {
        let cmd = Command::new("t").arg(
            Arg::new("format")
                .long("format")
                .value_parser(scan_format_parser())
                .ignore_case(true),
        );
        let matches = cmd.try_get_matches_from(["t", "--format", value])?;
        Ok(matches.get_one::<String>("format").unwrap().clone())
    }

    fn parse_db_show_format(value: &str) -> Result<String, clap::Error> {
        let cmd = Command::new("t").arg(
            Arg::new("format")
                .long("format")
                .value_parser(db_show_format_parser())
                .ignore_case(true),
        );
        let matches = cmd.try_get_matches_from(["t", "--format", value])?;
        Ok(matches.get_one::<String>("format").unwrap().clone())
    }

    fn parse_provider(value: &str) -> Result<String, clap::Error> {
        let cmd = Command::new("t").arg(
            Arg::new("provider")
                .long("provider")
                .value_parser(provider_parser())
                .ignore_case(true),
        );
        let matches = cmd.try_get_matches_from(["t", "--provider", value])?;
        Ok(matches.get_one::<String>("provider").unwrap().clone())
    }

    fn parse_help_subcommand(value: &str) -> Result<String, clap::Error> {
        let cmd = Command::new("t").arg(
            Arg::new("subcommand")
                .value_parser(help_subcommand_parser())
                .ignore_case(true),
        );
        let matches = cmd.try_get_matches_from(["t", value])?;
        Ok(matches.get_one::<String>("subcommand").unwrap().clone())
    }

    #[test]
    fn completion_omit_aliases_are_documented() {
        assert_eq!(
            COMPLETION_OMIT_ALIASES,
            &["list", "summary-file", "exit-code-on-cve"]
        );
    }

    #[test]
    fn scan_output_formats_match_runtime() {
        assert_eq!(SCAN_OUTPUT_FORMATS.len(), 6);
        assert!(SCAN_OUTPUT_FORMATS.contains(&"plain"));
        assert!(SCAN_OUTPUT_FORMATS.contains(&"json"));
        assert!(SCAN_OUTPUT_FORMATS.contains(&"sarif"));
        assert!(SCAN_OUTPUT_FORMATS.contains(&"cyclonedx"));
        assert!(SCAN_OUTPUT_FORMATS.contains(&"spdx"));
        assert!(SCAN_OUTPUT_FORMATS.contains(&"openvex"));
    }

    #[test]
    fn db_show_formats_contains_json_only() {
        assert_eq!(DB_SHOW_FORMATS, &["json"]);
    }

    #[test]
    fn help_subcommand_names_include_scan() {
        assert!(help_subcommand_names().contains(&"scan"));
        assert!(help_subcommand_names().contains(&"help"));
    }

    #[cfg(feature = "completions")]
    #[test]
    fn help_subcommand_names_include_generate_completions() {
        assert!(help_subcommand_names().contains(&"generate-completions"));
    }

    #[test]
    fn provider_names_starts_with_osv() {
        let names = provider_names();
        assert!(!names.is_empty());
        assert_eq!(names[0], "osv");
    }

    #[test]
    fn scan_format_parser_accepts_each_format() {
        for fmt in SCAN_OUTPUT_FORMATS {
            let parsed = parse_scan_format(fmt)
                .unwrap_or_else(|e| panic!("{fmt}: {e}"));
            assert_eq!(parsed.to_ascii_lowercase(), *fmt);
        }
    }

    #[test]
    fn scan_format_parser_ignore_case() {
        let parsed = parse_scan_format("JSON").unwrap();
        assert_eq!(parsed, "JSON");
    }

    #[test]
    fn scan_format_parser_rejects_html() {
        assert!(parse_scan_format("html").is_err());
    }

    #[test]
    fn scan_format_parser_rejects_empty() {
        assert!(parse_scan_format("").is_err());
    }

    #[test]
    fn db_show_format_parser_accepts_json() {
        let parsed = parse_db_show_format("json").unwrap();
        assert_eq!(parsed, "json");
    }

    #[test]
    fn db_show_format_parser_rejects_plain() {
        assert!(parse_db_show_format("plain").is_err());
    }

    #[test]
    fn provider_parser_accepts_osv() {
        let parsed = parse_provider("osv").unwrap();
        assert_eq!(parsed, "osv");
    }

    #[test]
    fn provider_parser_rejects_unknown() {
        assert!(parse_provider("nonexistentprovider").is_err());
    }

    #[test]
    fn providers_list_parser_accepts_all_and_osv() {
        assert_eq!(parse_providers_list_arg("all").unwrap(), "all");
        assert_eq!(parse_providers_list_arg("osv").unwrap(), "osv");
        assert_eq!(parse_providers_list_arg("osv, all").unwrap(), "osv, all");
        assert!(parse_providers_list_arg(",,").is_err());
        assert!(parse_providers_list_arg("not-a-provider").is_err());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn provider_names_include_testing_mocks() {
        for name in TESTING_PROVIDER_NAMES {
            assert!(provider_names().contains(name));
        }
    }

    #[cfg(feature = "testing")]
    #[test]
    fn provider_parser_accepts_cve_returning_when_testing() {
        let parsed = parse_provider("cve_returning").unwrap();
        assert_eq!(parsed, "cve_returning");
    }

    #[cfg(feature = "nvd")]
    #[test]
    fn provider_parser_accepts_nvd_when_feature_enabled() {
        assert!(provider_names().contains(&"nvd"));
        let parsed = parse_provider("nvd").unwrap();
        assert_eq!(parsed, "nvd");
    }

    #[test]
    fn help_subcommand_parser_accepts_scan() {
        let parsed = parse_help_subcommand("scan").unwrap();
        assert_eq!(parsed, "scan");
    }

    #[test]
    fn help_subcommand_parser_rejects_garbage() {
        assert!(parse_help_subcommand("not-a-command").is_err());
    }

    #[test]
    fn help_subcommand_parser_accepts_each_listed_name() {
        for name in help_subcommand_names() {
            let parsed = parse_help_subcommand(name)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(parsed, *name);
        }
    }
}
