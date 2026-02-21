// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser as ClapParser, Subcommand};

/// Parse KEY=VALUE for `config --set`. Returns None if key is empty or no `=` present.
pub fn parse_config_set_arg(pair: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = pair.splitn(2, '=').map(str::trim).collect();
    match parts[..] {
        [k, v] if !k.is_empty() => Some((k, v)),
        _ => None,
    }
}

#[derive(ClapParser, Debug)]
#[command(name = "vlz", version, author, about = "verilyze -- fast SCA")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,

    /// Increase verbosity (multiple times = more detail)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Override configuration file location
    #[arg(short, long, value_name = "PATH", global = true)]
    pub config: Option<String>,

    /// Set environment variable overrides (VLZ_*)
    #[arg(long, hide = true)]
    pub env_overrides: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a directory tree for manifests and CVEs
    Scan {
        /// Root directory (defaults to current working dir)
        #[arg(value_name = "PATH")]
        root: Option<String>,

        /// Output format (plain, json, sarif, cyclonedx, spdx)
        #[arg(long, default_value = "plain")]
        format: String,

        /// Generate additional files: e.g. html:/tmp/out.html,cyclonedx:/tmp/sbom.json
        #[arg(long, value_name = "TYPE:PATH")]
        summary_file: Vec<String>,

        /// Force a particular CVE provider
        #[arg(long)]
        provider: Option<String>,

        /// Parallel query limit (default 10, max 50)
        #[arg(long)]
        parallel: Option<usize>,

        /// Override cache database path
        #[arg(long, value_name = "PATH")]
        cache_db: Option<String>,

        /// Override ignore (false-positive) database path
        #[arg(long, value_name = "PATH")]
        ignore_db: Option<String>,

        /// Default TTL in seconds for new cache entries (default: 432000 = 5 days).
        /// Does not change existing entries; use `vlz db set-ttl` to update those.
        #[arg(long, value_name = "SECS")]
        cache_ttl_secs: Option<u64>,

        /// Disable network access
        #[arg(long)]
        offline: bool,

        /// Benchmark mode (no cache, no network, parallel=1)
        #[arg(long)]
        benchmark: bool,

        /// Minimum CVSS score to count toward exit code
        #[arg(long, value_name = "SCORE")]
        min_score: Option<f32>,

        /// Minimum count of CVEs meeting min-score to trigger CVE exit code (0 = any)
        #[arg(long, value_name = "N")]
        min_count: Option<usize>,

        /// Exit code when CVEs meet threshold (default 86)
        #[arg(long, value_name = "CODE")]
        exit_code_on_cve: Option<u8>,

        /// Exit code when only false-positives are present (default 0)
        #[arg(long, value_name = "CODE")]
        fp_exit_code: Option<u8>,

        /// Require package manager on PATH; exit 3 with hint if missing
        #[arg(long)]
        package_manager_required: bool,

        /// Base delay in ms for retry backoff (default 100)
        #[arg(long, value_name = "MS")]
        backoff_base: Option<u64>,

        /// Maximum delay in ms for retry backoff (default 30000)
        #[arg(long, value_name = "MS")]
        backoff_max: Option<u64>,

        /// Maximum retries for transient errors (default 5)
        #[arg(long, value_name = "N")]
        max_retries: Option<u32>,
    },

    /// List registered language/plugin names
    List,

    /// Show or set configuration values
    Config {
        #[arg(long)]
        list: bool,

        /// Set a key (e.g. python.regex="^requirements\\.txt$")
        #[arg(long, value_name = "KEY=VALUE")]
        set: Option<String>,
    },

    /// Database sub‑commands (stats, verify, migrate, list-providers, …)
    Db {
        #[command(subcommand)]
        sub: DbCommands,

        /// Default TTL in seconds when opening the cache (default: 432000 = 5 days).
        /// Does not change existing entries; use `vlz db set-ttl` to update those.
        #[arg(long, value_name = "SECS")]
        cache_ttl_secs: Option<u64>,
    },

    /// False-positive markings
    Fp {
        #[command(subcommand)]
        sub: FpCommands,
    },

    /// Pre-populate CVE cache from remote provider (placeholder)
    Preload,

    /// Show version / license information
    Version,
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
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        /// Include full CVE payload for each entry
        #[arg(long)]
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
    fn parse_list() {
        let cli = parse(&["list"]);
        assert!(matches!(cli.cmd, Commands::List));
    }

    #[test]
    fn parse_version() {
        let cli = parse(&["version"]);
        assert!(matches!(cli.cmd, Commands::Version));
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
    fn parse_scan_with_options() {
        let cli = parse(&["scan", "/tmp", "--format", "json", "--parallel", "5"]);
        let Commands::Scan {
            root,
            format,
            parallel,
            ..
        } = &cli.cmd
        else {
            panic!("expected scan")
        };
        assert_eq!(root.as_deref(), Some("/tmp"));
        assert_eq!(format, "json");
        assert_eq!(*parallel, Some(5));
    }

    #[test]
    fn parse_config_list() {
        let cli = parse(&["config", "--list"]);
        let Commands::Config { list, set } = &cli.cmd else {
            panic!("expected config")
        };
        assert!(*list);
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
        let cli = parse(&["-c", "/etc/vlz.toml", "list"]);
        assert_eq!(cli.config.as_deref(), Some("/etc/vlz.toml"));
        assert!(matches!(cli.cmd, Commands::List));
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
}
