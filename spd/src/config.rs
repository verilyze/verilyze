// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
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
    /// Exit code when only false-positives are present (FR-016; default 0).
    pub fp_exit_code: Option<u8>,
    /// Per-language manifest regex patterns (FR-006); order = first match wins.
    pub language_regexes: Vec<(String, String)>,
    /// If true, exit 3 with hint when required package manager (e.g. pip) is not on PATH (FR-024).
    pub package_manager_required: bool,
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
    #[serde(rename = "fp_exit_code")]
    fp_exit_code: Option<u8>,
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

/// When true, also extract [lang].regex into language_regexes (only from user config).
fn apply_file_config(
    cfg: &mut EffectiveConfig,
    raw: &str,
    path: &Path,
    source: &str,
    extract_language_regexes: bool,
) -> Result<(), ConfigError> {
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
    if let Some(c) = parsed.fp_exit_code {
        cfg.fp_exit_code = Some(c);
    }
    if extract_language_regexes {
        cfg.language_regexes.clear();
        if let Ok(value) = raw.parse::<toml::Value>() {
            if let Some(t) = value.as_table() {
                for (lang, table) in t {
                    if let Some(tbl) = table.as_table() {
                        if let Some(r) = tbl.get("regex").and_then(|v| v.as_str()) {
                            cfg.language_regexes.push((lang.clone(), r.to_string()));
                        }
                    }
                }
            }
        }
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
    env_cache_ttl_secs: Option<u64>,
    env_min_score: Option<f32>,
    env_min_count: Option<usize>,
    env_exit_code_on_cve: Option<u8>,
    env_fp_exit_code: Option<u8>,
    cli_parallel: Option<usize>,
    cli_cache_db: Option<&str>,
    cli_ignore_db: Option<&str>,
    cli_cache_ttl_secs: Option<u64>,
    cli_offline: bool,
    cli_benchmark: bool,
    cli_min_score: Option<f32>,
    cli_min_count: Option<usize>,
    cli_exit_code_on_cve: Option<u8>,
    cli_fp_exit_code: Option<u8>,
    cli_package_manager_required: bool,
) -> Result<EffectiveConfig, ConfigError> {
    let mut cfg = EffectiveConfig {
        parallel_queries: DEFAULT_PARALLEL_QUERIES,
        cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
        ..Default::default()
    };

    // 1) System config
    let sys_path = system_config_path();
    if let Ok(Some(ref raw)) = load_file_opt(&sys_path) {
        apply_file_config(&mut cfg, raw.as_str(), &sys_path, "system", false)?;
    }

    // 2) User config, or -c file if supplied (same precedence level)
    let user_path = user_config_path();
    let path_to_load = config_file_override
        .map(PathBuf::from)
        .unwrap_or_else(|| user_path.clone());
    if let Ok(Some(ref raw)) = load_file_opt(&path_to_load) {
        apply_file_config(&mut cfg, raw.as_str(), &path_to_load, "user", true)?;
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
    if let Some(n) = env_cache_ttl_secs {
        cfg.cache_ttl_secs = n;
    }
    if let Some(s) = env_min_score {
        cfg.min_score = s;
    }
    if let Some(n) = env_min_count {
        cfg.min_count = n;
    }
    if let Some(c) = env_exit_code_on_cve {
        cfg.exit_code_on_cve = Some(c);
    }
    if let Some(c) = env_fp_exit_code {
        cfg.fp_exit_code = Some(c);
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
    if let Some(n) = cli_cache_ttl_secs {
        cfg.cache_ttl_secs = n;
    }
    cfg.offline = cli_offline;
    cfg.benchmark = cli_benchmark;
    if let Some(s) = cli_min_score {
        cfg.min_score = s;
    }
    if let Some(n) = cli_min_count {
        cfg.min_count = n;
    }
    if let Some(c) = cli_exit_code_on_cve {
        cfg.exit_code_on_cve = Some(c);
    }
    if let Some(c) = cli_fp_exit_code {
        cfg.fp_exit_code = Some(c);
    }
    cfg.package_manager_required = cli_package_manager_required;

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
    std::env::var("SPD_PARALLEL_QUERIES")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_cache_db() -> Option<PathBuf> {
    std::env::var("SPD_CACHE_DB").ok().map(PathBuf::from)
}

pub fn env_ignore_db() -> Option<PathBuf> {
    std::env::var("SPD_IGNORE_DB").ok().map(PathBuf::from)
}

/// Read SPD_CACHE_TTL_SECS (OP-011, CFG-005).
pub fn env_cache_ttl_secs() -> Option<u64> {
    std::env::var("SPD_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_min_score() -> Option<f32> {
    std::env::var("SPD_MIN_SCORE")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_min_count() -> Option<usize> {
    std::env::var("SPD_MIN_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_exit_code_on_cve() -> Option<u8> {
    std::env::var("SPD_EXIT_CODE_ON_CVE")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_fp_exit_code() -> Option<u8> {
    std::env::var("SPD_FP_EXIT_CODE")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Set a config key (e.g. python.regex) in the user config file (FR-006).
pub fn set_config_key(key: &str, value: &str) -> Result<(), ConfigError> {
    let path = user_config_path();
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let raw = load_file_opt(&path)?.unwrap_or_else(|| String::new());
    let mut root: toml::Value = if raw.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        raw.parse()
            .map_err(|e: toml::de::Error| ConfigError::InvalidToml {
                path: path.clone(),
                message: e.to_string(),
            })?
    };
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ConfigError::UnknownKey {
            key: key.to_string(),
            origin: "config set".to_string(),
        });
    }
    let (table_key, sub_key) = (parts[0], parts[1]);
    let table = root
        .as_table_mut()
        .ok_or_else(|| ConfigError::InvalidToml {
            path: path.clone(),
            message: "root is not a table".to_string(),
        })?;
    let entry = table
        .entry(table_key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let inner = entry
        .as_table_mut()
        .ok_or_else(|| ConfigError::UnknownKey {
            key: key.to_string(),
            origin: "config set".to_string(),
        })?;
    inner.insert(sub_key.to_string(), toml::Value::String(value.to_string()));
    let out = toml::ser::to_string_pretty(&root).map_err(|e| ConfigError::InvalidToml {
        path: path.clone(),
        message: e.to_string(),
    })?;
    std::fs::write(&path, out)?;
    Ok(())
}
