// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "completions")]
use clap::value_parser;
use clap::{Parser as ClapParser, Subcommand, ValueHint};
#[cfg(feature = "completions")]
use clap_complete::Shell;

use crate::cli_values::{
    db_show_format_parser, help_subcommand_parser, provider_parser,
    scan_format_parser,
};

/// Parse KEY=VALUE for `config --set`. Returns None if key is empty or no `=` present.
pub fn parse_config_set_arg(pair: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = pair.splitn(2, '=').map(str::trim).collect();
    match parts[..] {
        [k, v] if !k.is_empty() => Some((k, v)),
        _ => None,
    }
}

/// MOD-009: URL for documentation when built without docs feature.
pub use vlz_report::VLZ_REPOSITORY_URL as DOCS_ONLINE_URL;

const HELP_OUTPUT: &str = "Output";
const HELP_THRESHOLDS: &str = "Thresholds";
const HELP_FALSE_POSITIVES: &str = "False positives";
const HELP_PROVIDER_CACHE: &str = "Provider and cache";
const HELP_RESOLUTION: &str = "Resolution";
const HELP_ANALYSIS: &str = "Analysis";
const HELP_SEVERITY_MAPPING: &str = "Severity mapping";
const HELP_ADVANCED: &str = "Advanced";

#[derive(ClapParser, Debug)]
#[command(
    name = "vlz",
    version,
    author,
    about = "Scan project dependencies for known vulnerabilities"
)]
#[command(disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,

    /// Increase verbosity (multiple times = more detail)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Override configuration file location
    #[arg(short, long, value_name = "PATH", global = true, value_hint = ValueHint::FilePath)]
    pub config: Option<String>,

    /// Set environment variable overrides (VLZ_*)
    #[arg(long, hide = true)]
    pub env_overrides: Vec<String>,
}

// The Scan variant is intentionally large (it carries all scan parameters).
// Boxing fields would add heap indirection with no runtime benefit for a CLI struct
// that is constructed exactly once per invocation.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan project dependencies for known vulnerabilities
    Scan {
        /// Root directory (defaults to current working dir)
        #[arg(value_name = "PATH", value_hint = ValueHint::DirPath)]
        root: Option<String>,

        /// Output format (plain, json, sarif, cyclonedx, spdx)
        #[arg(
            short,
            long,
            default_value = "plain",
            value_parser = scan_format_parser(),
            ignore_case = true,
            help_heading = HELP_OUTPUT,
        )]
        format: String,

        /// Write primary report to file instead of stdout
        #[arg(
            short,
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_OUTPUT,
        )]
        output: Option<String>,

        /// Write additional report files: e.g. html:/tmp/out.html,cyclonedx:/tmp/sbom.json
        #[arg(
            short = 's',
            long = "report",
            visible_alias = "summary-file",
            value_name = "TYPE:PATH",
            help_heading = HELP_OUTPUT,
        )]
        report: Vec<String>,

        /// Force a particular vulnerability provider
        #[arg(
            long,
            value_parser = provider_parser(),
            ignore_case = true,
            help_heading = HELP_PROVIDER_CACHE,
        )]
        provider: Option<String>,

        /// Parallel query limit (default 10, max 50)
        #[arg(short = 'j', long, help_heading = HELP_PROVIDER_CACHE)]
        parallel: Option<usize>,

        /// Parallel dependency resolution limit (default: CPU count, max 32)
        #[arg(long, value_name = "N", help_heading = HELP_RESOLUTION)]
        parallel_resolutions: Option<usize>,

        /// Override cache database path
        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_PROVIDER_CACHE,
        )]
        cache_db: Option<String>,

        /// Override ignore (false-positive) database path
        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_PROVIDER_CACHE,
        )]
        ignore_db: Option<String>,

        /// Exclude directory name from manifest discovery (repeatable)
        #[arg(
            long,
            value_name = "DIR",
            value_hint = ValueHint::DirPath,
            help_heading = HELP_RESOLUTION,
        )]
        scan_exclude_dir: Vec<String>,

        /// Only discover/merge listed Python lock file basenames (repeatable)
        #[arg(
            long = "lock-file",
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_RESOLUTION,
        )]
        lock_file: Vec<String>,

        /// Default TTL in seconds for new cache entries (default: 432000 = 5 days).
        /// Does not change existing entries; use `vlz db set-ttl` to update those.
        #[arg(long, value_name = "SECS", help_heading = HELP_PROVIDER_CACHE)]
        cache_ttl_secs: Option<u64>,

        /// Disable network access
        #[arg(long, help_heading = HELP_PROVIDER_CACHE)]
        offline: bool,

        /// Benchmark mode (no cache, no network, parallel=1)
        #[arg(long, help_heading = HELP_ADVANCED)]
        benchmark: bool,

        /// Minimum CVSS score to count toward exit code
        #[arg(long, value_name = "SCORE", help_heading = HELP_THRESHOLDS)]
        min_score: Option<f32>,

        /// Minimum count of CVEs meeting min-score to trigger CVE exit code (0 = any)
        #[arg(long, value_name = "N", help_heading = HELP_THRESHOLDS)]
        min_count: Option<usize>,

        /// Exit code when vulnerabilities meet threshold (default 86)
        #[arg(
            long = "exit-code",
            visible_alias = "exit-code-on-cve",
            value_name = "CODE",
            help_heading = HELP_THRESHOLDS,
        )]
        exit_code: Option<u8>,

        /// Exit code when only false-positives are present (default 0)
        #[arg(long, value_name = "CODE", help_heading = HELP_FALSE_POSITIVES)]
        fp_exit_code: Option<u8>,

        /// Project ID for false-positive scoping (FR-015); only FPs for this project or global apply
        #[arg(long, value_name = "ID", help_heading = HELP_FALSE_POSITIVES)]
        project_id: Option<String>,

        /// Require package manager on PATH; exit 3 with hint if missing
        #[arg(long, help_heading = HELP_RESOLUTION)]
        package_manager_required: bool,

        /// Do not remove ephemeral Python venv after scan (FR-023 debug)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        keep_ephemeral_venv: bool,

        /// Allow pip to execute dependency build code during resolution (SEC-023)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        allow_dependency_code_execution: bool,

        /// Fall back to direct-only scan with warning when transitive resolution fails (FR-022a).
        /// Applies to Python requirements.txt/Pipfile, Rust Cargo.toml without Cargo.lock,
        /// and Go go.mod when go list or cargo metadata cannot run.
        #[arg(long, help_heading = HELP_RESOLUTION)]
        allow_direct_only_fallback: bool,

        /// Stop on first manifest parse/resolution failure; skip CVE lookup (FR-037)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        fail_fast: bool,

        /// Base delay in ms for retry backoff (default 100)
        #[arg(long, value_name = "MS", help_heading = HELP_ADVANCED)]
        backoff_base: Option<u64>,

        /// Maximum delay in ms for retry backoff (default 30000)
        #[arg(long, value_name = "MS", help_heading = HELP_ADVANCED)]
        backoff_max: Option<u64>,

        /// Maximum retries for transient errors (default 5)
        #[arg(long, value_name = "N", help_heading = HELP_ADVANCED)]
        max_retries: Option<u32>,

        /// CVE provider HTTPS connect timeout in seconds (default 15)
        #[arg(long, value_name = "SECS", help_heading = HELP_ADVANCED)]
        provider_http_connect_timeout_secs: Option<u64>,

        /// CVE provider HTTPS total request timeout in seconds (default 120)
        #[arg(long, value_name = "SECS", help_heading = HELP_ADVANCED)]
        provider_http_request_timeout_secs: Option<u64>,

        /// PEM file of CRLs for optional Linux TLS certificate revocation (SEC-024)
        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_ADVANCED,
        )]
        tls_crl_bundle: Option<String>,

        /// Reachability analysis mode.
        #[arg(
            long,
            value_name = "MODE",
            value_parser = ["off", "tier-b", "best-available"],
            help_heading = HELP_ANALYSIS,
        )]
        reachability_mode: Option<String>,

        // FR-013: per-CVSS-version severity threshold overrides
        /// CVSS v2 critical severity minimum score (default 9.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v2_critical_min: Option<f32>,
        /// CVSS v2 high severity minimum score (default 7.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v2_high_min: Option<f32>,
        /// CVSS v2 medium severity minimum score (default 4.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v2_medium_min: Option<f32>,
        /// CVSS v2 low severity minimum score (default 0.1)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v2_low_min: Option<f32>,
        /// CVSS v3 critical severity minimum score (default 9.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v3_critical_min: Option<f32>,
        /// CVSS v3 high severity minimum score (default 7.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v3_high_min: Option<f32>,
        /// CVSS v3 medium severity minimum score (default 4.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v3_medium_min: Option<f32>,
        /// CVSS v3 low severity minimum score (default 0.1)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v3_low_min: Option<f32>,
        /// CVSS v4 critical severity minimum score (default 9.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v4_critical_min: Option<f32>,
        /// CVSS v4 high severity minimum score (default 7.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v4_high_min: Option<f32>,
        /// CVSS v4 medium severity minimum score (default 4.0)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v4_medium_min: Option<f32>,
        /// CVSS v4 low severity minimum score (default 0.1)
        #[arg(long, value_name = "SCORE", help_heading = HELP_SEVERITY_MAPPING)]
        severity_v4_low_min: Option<f32>,
    },

    /// List supported manifest languages
    #[command(visible_alias = "list")]
    Languages,

    /// Show or set configuration values
    Config {
        /// List effective configuration values
        #[arg(long)]
        list: bool,

        /// Output verilyze.conf.example with effective values for this environment
        #[arg(long)]
        example: bool,

        /// Set a key (e.g. python.regex="^requirements\\.txt$")
        #[arg(long, value_name = "KEY=VALUE")]
        set: Option<String>,
    },

    /// Inspect and maintain the vulnerability cache
    Db {
        #[command(subcommand)]
        sub: DbCommands,

        /// Default TTL in seconds when opening the cache (default: 432000 = 5 days).
        /// Does not change existing entries; use `vlz db set-ttl` to update those.
        #[arg(long, value_name = "SECS")]
        cache_ttl_secs: Option<u64>,
    },

    /// Manage false-positive vulnerability markings
    Fp {
        #[command(subcommand)]
        sub: FpCommands,
    },

    /// Resolve dependencies and warm the vulnerability cache (FR-021)
    Preload {
        /// Root directory (defaults to current working dir)
        #[arg(value_name = "PATH", value_hint = ValueHint::DirPath)]
        root: Option<String>,

        /// Force a particular vulnerability provider
        #[arg(
            long,
            value_parser = provider_parser(),
            ignore_case = true,
            help_heading = HELP_PROVIDER_CACHE,
        )]
        provider: Option<String>,

        /// Parallel query limit (default 10, max 50)
        #[arg(short = 'j', long, help_heading = HELP_PROVIDER_CACHE)]
        parallel: Option<usize>,

        /// Parallel dependency resolution limit (default: CPU count, max 32)
        #[arg(long, value_name = "N", help_heading = HELP_RESOLUTION)]
        parallel_resolutions: Option<usize>,

        /// Override cache database path
        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_PROVIDER_CACHE,
        )]
        cache_db: Option<String>,

        /// Exclude directory name from manifest discovery (repeatable)
        #[arg(
            long,
            value_name = "DIR",
            value_hint = ValueHint::DirPath,
            help_heading = HELP_RESOLUTION,
        )]
        scan_exclude_dir: Vec<String>,

        /// Only discover/merge listed Python lock file basenames (repeatable)
        #[arg(
            long = "lock-file",
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_RESOLUTION,
        )]
        lock_file: Vec<String>,

        /// Default TTL in seconds for new cache entries (default: 432000 = 5 days).
        #[arg(long, value_name = "SECS", help_heading = HELP_PROVIDER_CACHE)]
        cache_ttl_secs: Option<u64>,

        /// Disable network access
        #[arg(long, help_heading = HELP_PROVIDER_CACHE)]
        offline: bool,

        /// Require package manager on PATH; exit 3 with hint if missing
        #[arg(long, help_heading = HELP_RESOLUTION)]
        package_manager_required: bool,

        /// Do not remove ephemeral Python venv after resolution (FR-023 debug)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        keep_ephemeral_venv: bool,

        /// Allow pip to execute dependency build code during resolution (SEC-023)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        allow_dependency_code_execution: bool,

        /// Fall back to direct-only resolution with warning when transitive resolution fails (FR-022a)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        allow_direct_only_fallback: bool,

        /// Stop on first manifest parse/resolution failure (FR-037)
        #[arg(long, help_heading = HELP_RESOLUTION)]
        fail_fast: bool,

        /// Base delay in ms for retry backoff (default 100)
        #[arg(long, value_name = "MS", help_heading = HELP_ADVANCED)]
        backoff_base: Option<u64>,

        /// Maximum delay in ms for retry backoff (default 30000)
        #[arg(long, value_name = "MS", help_heading = HELP_ADVANCED)]
        backoff_max: Option<u64>,

        /// Maximum retries for transient errors (default 5)
        #[arg(long, value_name = "N", help_heading = HELP_ADVANCED)]
        max_retries: Option<u32>,

        /// Vulnerability provider HTTPS connect timeout in seconds (default 15)
        #[arg(long, value_name = "SECS", help_heading = HELP_ADVANCED)]
        provider_http_connect_timeout_secs: Option<u64>,

        /// Vulnerability provider HTTPS total request timeout in seconds (default 120)
        #[arg(long, value_name = "SECS", help_heading = HELP_ADVANCED)]
        provider_http_request_timeout_secs: Option<u64>,

        /// PEM file of CRLs for optional Linux TLS certificate revocation (SEC-024)
        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help_heading = HELP_ADVANCED,
        )]
        tls_crl_bundle: Option<String>,
    },

    /// Open the full manual page
    Help {
        #[arg(
            value_name = "SUBCOMMAND",
            value_parser = help_subcommand_parser(),
            ignore_case = true,
        )]
        subcommand: Option<String>,
    },

    /// Generate shell completion scripts
    #[cfg(feature = "completions")]
    GenerateCompletions {
        /// Shell (bash, zsh, fish)
        #[arg(value_name = "SHELL", value_parser = value_parser!(Shell))]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
pub enum FpCommands {
    /// Mark a CVE as false positive
    Mark {
        /// CVE ID (e.g. CVE-2023-1234)
        #[arg(value_name = "CVE-ID")]
        cve_id: String,

        /// Optional comment
        #[arg(long, default_value = "")]
        comment: String,

        /// Optional project scope
        #[arg(long, value_name = "ID")]
        project_id: Option<String>,
    },
    /// Remove false-positive marking for a CVE
    Unmark {
        /// CVE ID (e.g. CVE-2023-1234)
        #[arg(value_name = "CVE-ID")]
        cve_id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum DbCommands {
    Stats,
    Verify,
    Migrate,
    /// List supported CVE providers
    ListProviders,
    /// Display cache entries with TTL and added timestamp
    Show {
        /// Output format (e.g. json for full payload)
        #[arg(
            short,
            long,
            value_name = "FORMAT",
            value_parser = db_show_format_parser(),
            ignore_case = true,
            help_heading = HELP_OUTPUT,
        )]
        format: Option<String>,
        /// Include full CVE payload for each entry
        #[arg(long, help_heading = HELP_OUTPUT)]
        full: bool,
    },
    /// Update TTL for existing cache entries
    SetTtl {
        /// New TTL in seconds
        #[arg(value_name = "SECS")]
        secs: u64,
        /// Update a single entry by key (e.g. "name::version")
        #[arg(long, value_name = "KEY")]
        entry: Option<String>,
        /// Update all entries
        #[arg(long)]
        all: bool,
        /// Update entries matching pattern
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Update multiple entries (comma-separated keys)
        #[arg(long, value_name = "KEYS")]
        entries: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        let mut v = vec!["vlz"];
        v.extend(args.iter().copied());
        Cli::parse_from(v)
    }

    #[test]
    fn parse_languages() {
        let cli = parse(&["languages"]);
        assert!(matches!(cli.cmd, Commands::Languages));
    }

    #[test]
    fn parse_list_alias() {
        let cli = parse(&["list"]);
        assert!(matches!(cli.cmd, Commands::Languages));
    }

    #[test]
    fn version_flag_output_contains_semver() {
        // FR-002: --version must print "vlz <semver>". Clap derives the version
        // from CARGO_PKG_VERSION. Verify it contains a dotted semver string.
        use clap::CommandFactory as _;
        let rendered = Cli::command().render_version();
        assert!(
            rendered.starts_with("vlz "),
            "expected 'vlz <semver>' but got: {}",
            rendered.trim_end()
        );
        // Semver contains at least one dot (e.g. "0.1.0").
        let version_part = rendered.trim_start_matches("vlz ").trim_end();
        assert!(
            version_part.contains('.'),
            "version does not look like semver: {}",
            version_part
        );
    }

    #[test]
    fn version_subcommand_does_not_exist() {
        // FR-002: the redundant `vlz version` subcommand should not exist;
        // --version is the universal Unix convention (Rule of Parsimony).
        let result = Cli::try_parse_from(["vlz", "version"]);
        assert!(
            result.is_err(),
            "expected 'vlz version' to be an unknown subcommand"
        );
    }

    #[test]
    fn parse_scan_defaults() {
        let cli = parse(&["scan"]);
        let Commands::Scan { format, root, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(format, "plain");
        assert!(root.is_none());
    }

    #[test]
    fn parse_scan_backoff_options() {
        let cli = parse(&[
            "scan",
            "--backoff-base",
            "200",
            "--backoff-max",
            "10000",
            "--max-retries",
            "3",
        ]);
        let Commands::Scan {
            backoff_base,
            backoff_max,
            max_retries,
            ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(*backoff_base, Some(200));
        assert_eq!(*backoff_max, Some(10000));
        assert_eq!(*max_retries, Some(3));
    }

    #[test]
    fn parse_scan_provider_http_timeouts() {
        let cli = parse(&[
            "scan",
            "--provider-http-connect-timeout-secs",
            "30",
            "--provider-http-request-timeout-secs",
            "240",
        ]);
        let Commands::Scan {
            provider_http_connect_timeout_secs,
            provider_http_request_timeout_secs,
            ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(*provider_http_connect_timeout_secs, Some(30));
        assert_eq!(*provider_http_request_timeout_secs, Some(240));
    }

    #[test]
    fn parse_scan_tls_crl_bundle() {
        let cli = parse(&["scan", "--tls-crl-bundle", "/etc/pki/ca-crl.pem"]);
        let Commands::Scan { tls_crl_bundle, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(tls_crl_bundle.as_deref(), Some("/etc/pki/ca-crl.pem"));
    }

    #[test]
    fn parse_scan_short_flags_equivalent_to_long() {
        let cli = parse(&[
            "scan",
            "/tmp",
            "-f",
            "json",
            "-s",
            "html:/tmp/r.html",
            "-j",
            "5",
            "--min-score",
            "7.0",
        ]);
        let Commands::Scan {
            root,
            format,
            report,
            parallel,
            min_score,
            ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(root.as_deref(), Some("/tmp"));
        assert_eq!(format, "json");
        assert_eq!(report, &vec!["html:/tmp/r.html".to_string()]);
        assert_eq!(*parallel, Some(5));
        assert_eq!(*min_score, Some(7.0));
    }

    #[test]
    fn parse_scan_output_flag() {
        let cli = parse(&["scan", "-o", "/tmp/out.json"]);
        let Commands::Scan { output, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(output.as_deref(), Some("/tmp/out.json"));
    }

    #[test]
    fn parse_scan_report_and_summary_file_alias() {
        let cli = parse(&["scan", "--report", "json:/tmp/a.json"]);
        let Commands::Scan { report, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(report, &vec!["json:/tmp/a.json".to_string()]);

        let cli = parse(&["scan", "--summary-file", "sarif:/tmp/b.sarif"]);
        let Commands::Scan { report, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(report, &vec!["sarif:/tmp/b.sarif".to_string()]);
    }

    #[test]
    fn parse_scan_exit_code_canonical_and_alias() {
        let cli = parse(&["scan", "--exit-code", "99"]);
        let Commands::Scan { exit_code, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(*exit_code, Some(99));

        let cli = parse(&["scan", "--exit-code-on-cve", "88"]);
        let Commands::Scan { exit_code, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(*exit_code, Some(88));
    }

    #[test]
    fn parse_scan_min_score_short_flag_rejected() {
        let result = Cli::try_parse_from(["vlz", "scan", "-m", "7.0"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_global_verbose_before_subcommand() {
        let cli = parse(&["-v", "scan"]);
        assert_eq!(cli.verbose, 1);
        assert!(matches!(cli.cmd, Commands::Scan { .. }));
    }

    #[test]
    fn parse_verbose_after_subcommand() {
        let cli = parse(&["scan", "-v"]);
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn parse_db_show_short_format() {
        let cli = parse(&["db", "show", "-f", "json"]);
        let Commands::Db { sub, .. } = &cli.cmd else {
            panic!("expected db")
        };
        let DbCommands::Show { format, .. } = sub else {
            panic!("expected show")
        };
        assert_eq!(format.as_deref(), Some("json"));
    }

    #[test]
    fn parse_preload_short_parallel() {
        let cli = parse(&["preload", "-j", "12"]);
        let Commands::Preload { parallel, .. } = &cli.cmd else {
            panic!("expected preload")
        };
        assert_eq!(*parallel, Some(12));
    }

    #[test]
    fn parse_unknown_short_flag_fails() {
        let result = Cli::try_parse_from(["vlz", "scan", "-z"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_scan_with_options() {
        let cli =
            parse(&["scan", "/tmp", "--format", "json", "--parallel", "5"]);
        let Commands::Scan {
            root,
            format,
            parallel,
            reachability_mode,
            ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(root.as_deref(), Some("/tmp"));
        assert_eq!(format, "json");
        assert_eq!(*parallel, Some(5));
        assert!(reachability_mode.is_none());
    }

    #[test]
    fn parse_scan_with_reachability_mode() {
        let cli = parse(&["scan", "--reachability-mode", "best-available"]);
        let Commands::Scan {
            reachability_mode, ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(reachability_mode.as_deref(), Some("best-available"));
    }

    #[test]
    fn parse_scan_with_invalid_format_fails() {
        let result = Cli::try_parse_from(["vlz", "scan", "--format", "html"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_scan_format_ignore_case() {
        let cli = parse(&["scan", "--format", "JSON"]);
        let Commands::Scan { format, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(format, "JSON");
    }

    #[test]
    fn parse_scan_with_invalid_provider_fails() {
        let result = Cli::try_parse_from([
            "vlz",
            "scan",
            "--provider",
            "nonexistentprovider",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_scan_with_valid_provider() {
        let cli = parse(&["scan", "--provider", "osv"]);
        let Commands::Scan { provider, .. } = &cli.cmd else {
            panic!("expected scan")
        };
        assert_eq!(provider.as_deref(), Some("osv"));
    }

    #[test]
    fn parse_db_show_format_json() {
        let cli = parse(&["db", "show", "--format", "json"]);
        let Commands::Db { sub, .. } = &cli.cmd else {
            panic!("expected db")
        };
        let DbCommands::Show { format, .. } = sub else {
            panic!("expected show")
        };
        assert_eq!(format.as_deref(), Some("json"));
    }

    #[test]
    fn parse_db_show_invalid_format_fails() {
        let result =
            Cli::try_parse_from(["vlz", "db", "show", "--format", "plain"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_help_subcommand_valid() {
        let cli = parse(&["help", "scan"]);
        let Commands::Help { subcommand } = &cli.cmd else {
            panic!("expected help")
        };
        assert_eq!(subcommand.as_deref(), Some("scan"));
    }

    #[test]
    fn parse_help_subcommand_invalid_fails() {
        let result = Cli::try_parse_from(["vlz", "help", "not-a-command"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_scan_with_invalid_reachability_mode_fails() {
        let result = Cli::try_parse_from([
            "vlz",
            "scan",
            "--reachability-mode",
            "bad-tier",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_scan_with_excluded_dirs() {
        let cli = parse(&[
            "scan",
            "/tmp",
            "--scan-exclude-dir",
            ".git",
            "--scan-exclude-dir",
            "target",
        ]);
        let Commands::Scan {
            scan_exclude_dir, ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(
            scan_exclude_dir,
            &vec![".git".to_string(), "target".to_string()]
        );
    }

    #[test]
    fn parse_config_list() {
        let cli = parse(&["config", "--list"]);
        let Commands::Config { list, example, set } = &cli.cmd else {
            panic!("expected config")
        };
        assert!(*list);
        assert!(!*example);
        assert!(set.is_none());
    }

    #[test]
    fn parse_db_stats() {
        let cli = parse(&["db", "stats"]);
        let Commands::Db { sub, .. } = &cli.cmd else {
            panic!("expected db")
        };
        assert!(matches!(sub, DbCommands::Stats));
    }

    #[test]
    fn parse_db_show_full() {
        let cli = parse(&["db", "show", "--full"]);
        let Commands::Db { sub, .. } = &cli.cmd else {
            panic!("expected db")
        };
        let DbCommands::Show { full, .. } = sub else {
            panic!("expected show")
        };
        assert!(*full);
    }

    #[test]
    fn parse_fp_mark() {
        let cli = parse(&["fp", "mark", "CVE-2023-1234", "--comment", "fp"]);
        let Commands::Fp { sub } = &cli.cmd else {
            panic!("expected fp")
        };
        let FpCommands::Mark {
            cve_id, comment, ..
        } = sub
        else {
            panic!("expected mark")
        };
        assert_eq!(cve_id, "CVE-2023-1234");
        assert_eq!(comment, "fp");
    }

    #[test]
    fn parse_global_config() {
        let cli = parse(&["-c", "/etc/vlz.toml", "languages"]);
        assert_eq!(cli.config.as_deref(), Some("/etc/vlz.toml"));
        assert!(matches!(cli.cmd, Commands::Languages));
    }

    #[test]
    fn parse_help_subcommand_languages_and_list_alias() {
        let cli = parse(&["help", "languages"]);
        let Commands::Help { subcommand } = &cli.cmd else {
            panic!("expected help")
        };
        assert_eq!(subcommand.as_deref(), Some("languages"));

        let cli = parse(&["help", "list"]);
        let Commands::Help { subcommand } = &cli.cmd else {
            panic!("expected help")
        };
        assert_eq!(subcommand.as_deref(), Some("list"));
    }

    #[test]
    fn parse_config_set_arg_valid() {
        assert_eq!(parse_config_set_arg("a=b"), Some(("a", "b")));
        assert_eq!(parse_config_set_arg("key = val "), Some(("key", "val")));
        assert_eq!(parse_config_set_arg("x="), Some(("x", "")));
    }

    #[test]
    fn parse_config_set_arg_invalid() {
        assert_eq!(parse_config_set_arg(""), None);
        assert_eq!(parse_config_set_arg("=value"), None);
        assert_eq!(parse_config_set_arg("key"), None);
    }

    #[test]
    fn parse_help_subcommand() {
        let cli = parse(&["help"]);
        let Commands::Help { subcommand } = &cli.cmd else {
            panic!("expected help")
        };
        assert!(subcommand.is_none());
    }

    #[test]
    fn parse_help_subcommand_with_arg() {
        let cli = parse(&["help", "scan"]);
        let Commands::Help { subcommand } = &cli.cmd else {
            panic!("expected help")
        };
        assert_eq!(subcommand.as_deref(), Some("scan"));
    }

    #[test]
    fn parse_preload_defaults() {
        let cli = parse(&["preload"]);
        let Commands::Preload { root, offline, .. } = &cli.cmd else {
            panic!("expected preload")
        };
        assert!(root.is_none());
        assert!(!*offline);
    }

    #[test]
    fn parse_preload_with_path_and_cache_flags() {
        let cli = parse(&[
            "preload",
            "/tmp/proj",
            "--provider",
            "osv",
            "--parallel",
            "8",
            "--cache-db",
            "/tmp/cache.redb",
            "--offline",
            "--package-manager-required",
            "--allow-direct-only-fallback",
            "--fail-fast",
        ]);
        let Commands::Preload {
            root,
            provider,
            parallel,
            cache_db,
            offline,
            package_manager_required,
            allow_direct_only_fallback,
            fail_fast,
            ..
        } = &cli.cmd
        else {
            panic!("expected preload")
        };
        assert_eq!(root.as_deref(), Some("/tmp/proj"));
        assert_eq!(provider.as_deref(), Some("osv"));
        assert_eq!(*parallel, Some(8));
        assert_eq!(cache_db.as_deref(), Some("/tmp/cache.redb"));
        assert!(*offline);
        assert!(*package_manager_required);
        assert!(*allow_direct_only_fallback);
        assert!(*fail_fast);
    }

    #[test]
    fn parse_preload_resolution_and_provider_http_flags() {
        let cli = parse(&[
            "preload",
            "--parallel-resolutions",
            "4",
            "--scan-exclude-dir",
            "node_modules",
            "--lock-file",
            "pylock.toml",
            "--provider-http-connect-timeout-secs",
            "20",
            "--provider-http-request-timeout-secs",
            "90",
            "--tls-crl-bundle",
            "/etc/crl.pem",
            "--backoff-base",
            "150",
        ]);
        let Commands::Preload {
            parallel_resolutions,
            scan_exclude_dir,
            lock_file,
            provider_http_connect_timeout_secs,
            provider_http_request_timeout_secs,
            tls_crl_bundle,
            backoff_base,
            ..
        } = &cli.cmd
        else {
            panic!("expected preload")
        };
        assert_eq!(*parallel_resolutions, Some(4));
        assert_eq!(scan_exclude_dir, &vec!["node_modules".to_string()]);
        assert_eq!(lock_file, &vec!["pylock.toml".to_string()]);
        assert_eq!(*provider_http_connect_timeout_secs, Some(20));
        assert_eq!(*provider_http_request_timeout_secs, Some(90));
        assert_eq!(tls_crl_bundle.as_deref(), Some("/etc/crl.pem"));
        assert_eq!(*backoff_base, Some(150));
    }
}
