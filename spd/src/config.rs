//! Configuration loading with strict precedence (CFG-001–CFG-008).
//! Order: system → user → -c file → SPD_* env → CLI (later overrides earlier).

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Maximum allowed parallel queries (FR-012).
pub const MAX_PARALLEL_QUERIES: usize = 50;

/// Default parallel queries.
pub const DEFAULT_PARALLEL_QUERIES: usize = 10;

/// Default cache TTL in seconds (OP-009: 5 days).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 5 * 24 * 60 * 60;

#[derive(Debug, Clone, Default)]
pub struct EffectiveConfig {
    pub cache_db: Option<PathBuf>,
    pub ignore_db: Option<PathBuf>,
    pub parallel_queries: usize,
    pub cache_ttl_secs: u64,
    pub offline: bool,
    pub benchmark: bool,
    pub min_score: f32,
    pub min_count: usize,
    pub exit_code_on_cve: Option<u8>,
    pub config_file: Option<PathBuf>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(rename = "cache_db")]
    cache_db: Option<String>,
    #[serde(rename = "ignore_db")]
    ignore_db: Option<String>,
    #[serde(rename = "parallel_queries")]
    parallel_queries: Option<u32>,
    #[serde(rename = "cache_ttl_secs")]
    cache_ttl_secs: Option<u64>,
    #[serde(rename = "min_score")]
    min_score: Option<f32>,
    #[serde(rename = "min_count")]
    min_count: Option<usize>,
    #[serde(rename = "exit_code_on_cve")]
    exit_code_on_cve: Option<u8>,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid TOML in configuration file {path}: {message}")]
    InvalidToml { path: PathBuf, message: String },

    #[error("Unknown configuration key '{key}' (from {origin})")]
    UnknownKey { key: String, origin: String },

    #[error("Parallel queries must be at most {max}; got {value}")]
    ParallelTooHigh { value: usize, max: usize },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

fn apply_file_config(cfg: &mut EffectiveConfig, raw: &str, path: &Path, source: &str) -> Result<(), ConfigError> {
    let parsed: FileConfig = toml::from_str(raw).map_err(|e| ConfigError::InvalidToml {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    if let Some(p) = parsed.cache_db {
        cfg.cache_db = Some(PathBuf::from(p));
    }
    if let Some(p) = parsed.ignore_db {
        cfg.ignore_db = Some(PathBuf::from(p));
    }
    if let Some(n) = parsed.parallel_queries {
        cfg.parallel_queries = n as usize;
    }
    if let Some(n) = parsed.cache_ttl_secs {
        cfg.cache_ttl_secs = n;
    }
    if let Some(s) = parsed.min_score {
        cfg.min_score = s;
    }
    if let Some(n) = parsed.min_count {
        cfg.min_count = n;
    }
    if let Some(c) = parsed.exit_code_on_cve {
        cfg.exit_code_on_cve = Some(c);
    }
    let _ = source;
    Ok(())
}

fn load_file_opt(path: &Path) -> Result<Option<String>, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigError::Io(e)),
    }
}

/// System-wide config path (CFG-002).
fn system_config_path() -> PathBuf {
    PathBuf::from("/etc/super-duper.conf")
}

/// Per-user config path (CFG-003).
fn user_config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        })
        .join("super-duper")
        .join("super-duper.conf")
}

/// Default cache DB path (OP-002 privileged, OP-003 non-privileged).
pub fn default_cache_path() -> PathBuf {
    if is_privileged() {
        PathBuf::from("/var/cache/super-duper/spd-cache.redb")
    } else {
        cache_home().join("super-duper").join("spd-cache.redb")
    }
}

/// Default ignore (false-positive) DB path (OP-002, OP-003).
pub fn default_ignore_path() -> PathBuf {
    if is_privileged() {
        PathBuf::from("/var/lib/super-duper/spd-ignore.redb")
    } else {
        data_home().join("super-duper").join("spd-ignore.redb")
    }
}

fn is_privileged() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if line.starts_with("Uid:") {
                    let mut fields = line[4..].split_whitespace();
                    let _real = fields.next();
                    let effective = fields.next().and_then(|s| s.parse::<u32>().ok());
                    return effective == Some(0);
                }
            }
        }
        return false;
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    return false;
    #[cfg(not(unix))]
    return false;
}

fn cache_home() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cache")
        })
}

fn data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local")
                .join("share")
        })
}

/// Build effective config: defaults, then system file, user file, -c file, env, CLI.
/// Validates parallel_queries <= MAX_PARALLEL_QUERIES (FR-012).
pub fn load(
    config_file_override: Option<&str>,
    env_parallel: Option<usize>,
    env_cache_db: Option<PathBuf>,
    env_ignore_db: Option<PathBuf>,
    cli_parallel: Option<usize>,
    cli_cache_db: Option<&str>,
    cli_ignore_db: Option<&str>,
    cli_offline: bool,
    cli_benchmark: bool,
) -> Result<EffectiveConfig, ConfigError> {
    let mut cfg = EffectiveConfig {
        parallel_queries: DEFAULT_PARALLEL_QUERIES,
        cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
        ..Default::default()
    };

    // 1) System config
    let sys_path = system_config_path();
    if let Ok(Some(ref raw)) = load_file_opt(&sys_path) {
        apply_file_config(&mut cfg, raw.as_str(), &sys_path, "system")?;
    }

    // 2) User config, or -c file if supplied (same precedence level)
    let user_path = user_config_path();
    let path_to_load = config_file_override
        .map(PathBuf::from)
        .unwrap_or_else(|| user_path.clone());
    if let Ok(Some(ref raw)) = load_file_opt(&path_to_load) {
        apply_file_config(&mut cfg, raw.as_str(), &path_to_load, "user")?;
    }
    cfg.config_file = config_file_override.map(PathBuf::from);

    // 4) Environment (SPD_*)
    if let Some(n) = env_parallel {
        cfg.parallel_queries = n;
    }
    if let Some(p) = env_cache_db {
        cfg.cache_db = Some(p);
    }
    if let Some(p) = env_ignore_db {
        cfg.ignore_db = Some(p);
    }

    // 5) CLI
    if let Some(n) = cli_parallel {
        cfg.parallel_queries = n;
    }
    if let Some(p) = cli_cache_db {
        cfg.cache_db = Some(PathBuf::from(p));
    }
    if let Some(p) = cli_ignore_db {
        cfg.ignore_db = Some(PathBuf::from(p));
    }
    cfg.offline = cli_offline;
    cfg.benchmark = cli_benchmark;

    if cfg.parallel_queries > MAX_PARALLEL_QUERIES {
        return Err(ConfigError::ParallelTooHigh {
            value: cfg.parallel_queries,
            max: MAX_PARALLEL_QUERIES,
        });
    }

    Ok(cfg)
}

/// Read SPD_* environment variables for config (CFG-005).
pub fn env_parallel() -> Option<usize> {
    std::env::var("SPD_PARALLEL_QUERIES").ok().and_then(|s| s.parse().ok())
}

pub fn env_cache_db() -> Option<PathBuf> {
    std::env::var("SPD_CACHE_DB").ok().map(PathBuf::from)
}

pub fn env_ignore_db() -> Option<PathBuf> {
    std::env::var("SPD_IGNORE_DB").ok().map(PathBuf::from)
}
