//! Command‑line interface – mirrors FR‑001 … FR‑030.

use clap::{Parser as ClapParser, Subcommand};

#[derive(ClapParser, Debug)]
#[command(name = "spd", version, author, about = "Super‑Duper – fast SCA")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,

    /// Increase verbosity (multiple times = more detail)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Override configuration file location
    #[arg(short, long, value_name = "PATH")]
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

        /// Parallel query limit (default 10)
        #[arg(long, default_value_t = 10)]
        parallel: usize,

        /// Disable network access
        #[arg(long)]
        offline: bool,

        /// Benchmark mode (no cache, no network, parallel=1)
        #[arg(long)]
        benchmark: bool,
    },

    /// Show configuration values
    Config {
        #[arg(long)]
        list: bool,
    },

    /// Database sub‑commands (stats, verify, migrate, …)
    Db {
        #[command(subcommand)]
        sub: DbCommands,
    },

    /// Show version / licence information
    Version,
}

#[derive(Subcommand, Debug)]
pub enum DbCommands {
    Stats,
    Verify,
    Migrate,
}
