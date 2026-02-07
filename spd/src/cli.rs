// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

use clap::{Parser as ClapParser, Subcommand};

#[derive(ClapParser, Debug)]
#[command(name = "spd", version, author, about = "super‑duper – fast SCA")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,

    /// Increase verbosity (multiple times = more detail)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Override configuration file location
    #[arg(short, long, value_name = "PATH", global = true)]
    pub config: Option<String>,

    /// Set environment variable overrides (SPD_*)
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

        /// Output format (plain, json, sarif)
        #[arg(long, default_value = "plain")]
        format_type: String,

        /// Generate additional files: e.g. html:/tmp/out.html,json:/tmp/out.json
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
        /// Does not change existing entries; use `spd db set-ttl` to update those.
        #[arg(long, value_name = "SECS")]
        cache_ttl_secs: Option<u64>,

        /// Disable network access
        #[arg(long)]
        offline: bool,

        /// Benchmark mode (no cache, no network, parallel=1)
        #[arg(long)]
        benchmark: bool,

        /// Minimum CVSS score to count toward exit code (FR-014)
        #[arg(long, value_name = "SCORE")]
        min_score: Option<f32>,

        /// Minimum count of CVEs meeting min-score to trigger CVE exit code (0 = any)
        #[arg(long, value_name = "N")]
        min_count: Option<usize>,

        /// Exit code when CVEs meet threshold (default 86)
        #[arg(long, value_name = "CODE")]
        exit_code_on_cve: Option<u8>,

        /// Exit code when only false-positives are present (FR-016; default 0)
        #[arg(long, value_name = "CODE")]
        fp_exit_code: Option<u8>,

        /// Require package manager on PATH; exit 3 with hint if missing (FR-024)
        #[arg(long)]
        package_manager_required: bool,
    },

    /// List registered language/plugin names (FR-005)
    List,

    /// Show or set configuration values (FR-006)
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
        /// Does not change existing entries; use `spd db set-ttl` to update those.
        #[arg(long, value_name = "SECS")]
        cache_ttl_secs: Option<u64>,
    },

    /// False-positive markings (FR-015)
    Fp {
        #[command(subcommand)]
        sub: FpCommands,
    },

    /// Pre-populate CVE cache from remote provider (FR-021; placeholder)
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
        #[arg(short, long, default_value = "")]
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
    /// List supported CVE providers (FR-018)
    ListProviders,
    /// Display cache entries with TTL and added timestamp (FR-035)
    Show {
        /// Output format (e.g. json for full payload)
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        /// Include full CVE payload for each entry
        #[arg(long)]
        full: bool,
    },
    /// Update TTL for existing cache entries (OP-015)
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
