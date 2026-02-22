// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Format path for error output using ~ for home when applicable (NFR-018, SEC-020).
fn user_relative_path(path: &Path) -> String {
    let s = path.display().to_string();
    if let Some(home) = std::env::var_os("HOME") {
        let home_str = home.to_string_lossy();
        if !home_str.is_empty() && s.starts_with(&*home_str) {
            let rest = s[home_str.len()..].trim_start_matches('/');
            return if rest.is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", rest)
            };
        }
    }
    s
}

/// Maximum allowed parallel queries (FR-012).
pub const MAX_PARALLEL_QUERIES: usize = 50;

/// Default parallel queries.
pub const DEFAULT_PARALLEL_QUERIES: usize = 10;

/// Default cache TTL in seconds (OP-009: 5 days).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 5 * 24 * 60 * 60;

/// Default backoff base in milliseconds (SEC-007).
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 100;

/// Default backoff max in milliseconds.
pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;

/// Default max retries for transient errors (NFR-005, SEC-007).
pub const DEFAULT_MAX_RETRIES: u32 = 5;

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
    /// Backoff base delay in milliseconds (NFR-005, SEC-007, OP-010).
    pub backoff_base_ms: u64,
    /// Backoff maximum delay in milliseconds.
    pub backoff_max_ms: u64,
    /// Maximum retries for transient errors.
    pub max_retries: u32,
    pub config_file: Option<PathBuf>,
}

/// Parsed config file. Unknown top-level keys (e.g. [python] for language regexes) are
/// ignored here and extracted separately when extract_language_regexes is true.
#[derive(Debug, Default, serde::Deserialize)]
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
    #[serde(rename = "backoff_base_ms")]
    backoff_base_ms: Option<u64>,
    #[serde(rename = "backoff_max_ms")]
    backoff_max_ms: Option<u64>,
    #[serde(rename = "max_retries")]
    max_retries: Option<u32>,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid TOML in configuration file {path_display}: {message}")]
    InvalidToml {
        path: PathBuf,
        path_display: String,
        message: String,
    },

    #[error("Unknown configuration key '{key}' (from {origin})")]
    UnknownKey { key: String, origin: String },

    #[error("Parallel queries must be at most {max}; got {value}")]
    ParallelTooHigh { value: usize, max: usize },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Top-level keys that are known scalar/config entries (SEC-006: reject unknown keys).
const KNOWN_FILE_CONFIG_KEYS: &[&str] = &[
    "cache_db",
    "ignore_db",
    "parallel_queries",
    "cache_ttl_secs",
    "min_score",
    "min_count",
    "exit_code_on_cve",
    "fp_exit_code",
    "backoff_base_ms",
    "backoff_max_ms",
    "max_retries",
];

/// Parse and validate raw TOML config content (SEC-006). Used for fuzzing (NFR-020).
/// Does not perform file I/O; uses a synthetic path for error messages.
pub fn parse_and_validate_toml(raw: &str) -> Result<(), ConfigError> {
    let path = Path::new("<fuzz>");
    let mut cfg = EffectiveConfig::default();
    apply_file_config(&mut cfg, raw, path, "fuzz", true)
}

/// Inner implementation of apply_file_config. Panics from the toml crate (e.g. on
/// malformed numbers like `0onccbttj`) are caught by apply_file_config and
/// converted to InvalidToml (SEC-017).
fn apply_file_config_inner(
    cfg: &mut EffectiveConfig,
    raw: &str,
    path: &Path,
    source: &str,
    extract_language_regexes: bool,
) -> Result<(), ConfigError> {
    let parsed: FileConfig = toml::from_str(raw).map_err(|e| ConfigError::InvalidToml {
        path: path.to_path_buf(),
        path_display: user_relative_path(path),
        message: e.to_string(),
    })?;
    // SEC-006: reject unknown keys. Allow only known scalars and [lang] tables.
    // Use toml::from_str (same as FileConfig) so we get the same parse behavior.
    if let Ok(value) = toml::from_str::<toml::Value>(raw) {
        if let Some(t) = value.as_table() {
            for (key, val) in t.iter() {
                if KNOWN_FILE_CONFIG_KEYS.contains(&key.as_str()) {
                    continue;
                }
                if val.is_table() {
                    continue; // [lang] sections allowed
                }
                return Err(ConfigError::UnknownKey {
                    key: key.clone(),
                    origin: source.to_string(),
                });
            }
        }
    }
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
    if let Some(n) = parsed.backoff_base_ms {
        cfg.backoff_base_ms = n;
    }
    if let Some(n) = parsed.backoff_max_ms {
        cfg.backoff_max_ms = n;
    }
    if let Some(n) = parsed.max_retries {
        cfg.max_retries = n;
    }
    if extract_language_regexes {
        cfg.language_regexes.clear();
        if let Ok(value) = toml::from_str::<toml::Value>(raw) {
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

/// When true, also extract [lang].regex into language_regexes (only from user config).
/// Catches panics from the toml crate (e.g. malformed numbers) and converts to
/// InvalidToml (SEC-017: user-friendly error instead of crash).
fn apply_file_config(
    cfg: &mut EffectiveConfig,
    raw: &str,
    path: &Path,
    source: &str,
    extract_language_regexes: bool,
) -> Result<(), ConfigError> {
    let path_buf = path.to_path_buf();
    let path_display = user_relative_path(path);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        apply_file_config_inner(cfg, raw, path, source, extract_language_regexes)
    })) {
        Ok(r) => r,
        Err(_) => Err(ConfigError::InvalidToml {
            path: path_buf,
            path_display,
            message: "invalid input caused parser error".to_string(),
        }),
    }
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
    PathBuf::from("/etc/verilyze.conf")
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
        .join("verilyze")
        .join("verilyze.conf")
}

/// Default cache DB path (OP-002 privileged, OP-003 non-privileged).
pub fn default_cache_path() -> PathBuf {
    if is_privileged() {
        PathBuf::from("/var/cache/verilyze/vlz-cache.redb")
    } else {
        cache_home().join("verilyze").join("vlz-cache.redb")
    }
}

/// Default ignore (false-positive) DB path (OP-002, OP-003).
pub fn default_ignore_path() -> PathBuf {
    if is_privileged() {
        PathBuf::from("/var/lib/verilyze/vlz-ignore.redb")
    } else {
        data_home().join("verilyze").join("vlz-ignore.redb")
    }
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static MOCK_PRIVILEGED: std::cell::RefCell<Option<bool>> =
        std::cell::RefCell::new(None);
}

/// Set mock privileged state for tests. Call with Some(true) to simulate root,
/// Some(false) to force non-root, None to use real implementation.
#[cfg(any(test, feature = "testing"))]
pub fn set_mock_privileged(value: Option<bool>) {
    MOCK_PRIVILEGED.with(|c| *c.borrow_mut() = value);
}

fn is_privileged() -> bool {
    #[cfg(any(test, feature = "testing"))]
    {
        if let Some(v) = MOCK_PRIVILEGED.with(|c| *c.borrow()) {
            return v;
        }
    }
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
    env_backoff_base_ms: Option<u64>,
    env_backoff_max_ms: Option<u64>,
    env_max_retries: Option<u32>,
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
    cli_backoff_base_ms: Option<u64>,
    cli_backoff_max_ms: Option<u64>,
    cli_max_retries: Option<u32>,
) -> Result<EffectiveConfig, ConfigError> {
    let mut cfg = EffectiveConfig {
        parallel_queries: DEFAULT_PARALLEL_QUERIES,
        cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
        backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
        backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
        max_retries: DEFAULT_MAX_RETRIES,
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

    // 4) Environment (VLZ_*)
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
    if let Some(n) = env_backoff_base_ms {
        cfg.backoff_base_ms = n;
    }
    if let Some(n) = env_backoff_max_ms {
        cfg.backoff_max_ms = n;
    }
    if let Some(n) = env_max_retries {
        cfg.max_retries = n;
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
    if let Some(n) = cli_backoff_base_ms {
        cfg.backoff_base_ms = n;
    }
    if let Some(n) = cli_backoff_max_ms {
        cfg.backoff_max_ms = n;
    }
    if let Some(n) = cli_max_retries {
        cfg.max_retries = n;
    }

    if cfg.parallel_queries > MAX_PARALLEL_QUERIES {
        return Err(ConfigError::ParallelTooHigh {
            value: cfg.parallel_queries,
            max: MAX_PARALLEL_QUERIES,
        });
    }

    Ok(cfg)
}

/// Read VLZ_* environment variables for config (CFG-005).
pub fn env_parallel() -> Option<usize> {
    std::env::var("VLZ_PARALLEL_QUERIES")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_cache_db() -> Option<PathBuf> {
    std::env::var("VLZ_CACHE_DB").ok().map(PathBuf::from)
}

pub fn env_ignore_db() -> Option<PathBuf> {
    std::env::var("VLZ_IGNORE_DB").ok().map(PathBuf::from)
}

/// Read VLZ_CACHE_TTL_SECS (OP-011, CFG-005).
pub fn env_cache_ttl_secs() -> Option<u64> {
    std::env::var("VLZ_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_min_score() -> Option<f32> {
    std::env::var("VLZ_MIN_SCORE")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_min_count() -> Option<usize> {
    std::env::var("VLZ_MIN_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_exit_code_on_cve() -> Option<u8> {
    std::env::var("VLZ_EXIT_CODE_ON_CVE")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn env_fp_exit_code() -> Option<u8> {
    std::env::var("VLZ_FP_EXIT_CODE")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Read VLZ_BACKOFF_BASE_MS (OP-010, CFG-005).
pub fn env_backoff_base_ms() -> Option<u64> {
    std::env::var("VLZ_BACKOFF_BASE_MS")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Read VLZ_BACKOFF_MAX_MS (OP-010, CFG-005).
pub fn env_backoff_max_ms() -> Option<u64> {
    std::env::var("VLZ_BACKOFF_MAX_MS")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Read VLZ_MAX_RETRIES (OP-010, CFG-005).
pub fn env_max_retries() -> Option<u32> {
    std::env::var("VLZ_MAX_RETRIES")
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
    // toml 1.0: Value::FromStr parses single values; use Table for documents.
    let mut root: toml::Table = if raw.trim().is_empty() {
        toml::Table::new()
    } else {
        toml::from_str(&raw).map_err(|e: toml::de::Error| ConfigError::InvalidToml {
            path: path.clone(),
            path_display: user_relative_path(&path),
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
    let entry = root
        .entry(table_key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let inner = entry
        .as_table_mut()
        .ok_or_else(|| ConfigError::UnknownKey {
            key: key.to_string(),
            origin: "config set".to_string(),
        })?;
    inner.insert(sub_key.to_string(), toml::Value::String(value.to_string()));
    let out = toml::to_string_pretty(&root).map_err(|e| ConfigError::InvalidToml {
        path: path.clone(),
        path_display: user_relative_path(&path),
        message: e.to_string(),
    })?;
    std::fs::write(&path, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_defaults_when_no_files() {
        let cfg = load(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, DEFAULT_PARALLEL_QUERIES);
        assert_eq!(cfg.cache_ttl_secs, DEFAULT_CACHE_TTL_SECS);
        assert_eq!(cfg.backoff_base_ms, DEFAULT_BACKOFF_BASE_MS);
        assert_eq!(cfg.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn load_parallel_too_high_fr012() {
        let r = load(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(51),
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
        );
        assert!(matches!(
            r,
            Err(ConfigError::ParallelTooHigh { value: 51, max: 50 })
        ));
    }

    #[test]
    fn parse_and_validate_toml_malformed_number_returns_error_sec017() {
        // Input that triggers toml_parser panic (e.g. "0onccbttj" after =).
        // SEC-017: we must return error, not panic.
        let r = parse_and_validate_toml(
            "min_score =0onccbttj_secs = 8\nmin_count = 33333333333333333333333333",
        );
        assert!(r.is_err());
    }

    #[test]
    fn parse_and_validate_toml_malformed_fuzz_inputs_returns_error_sec017() {
        // Additional fuzz crash inputs - must return error, not panic.
        let inputs = [
            r#"min__count =[3
 pu =...........................ex = "^requirements\\.txt$""#,
            r#"cs = 0b = " ==[ps = 20"#,
            r#"parallel_queries = 100000000000000"#,
            r#"min_count = 33333333333333333333333333"#,
        ];
        for input in inputs {
            let r = parse_and_validate_toml(input);
            assert!(r.is_err(), "input should error: {:?}", input);
        }
    }

    #[test]
    fn set_config_key_invalid_key_returns_unknown_key() {
        let dir = tempfile::tempdir().unwrap();
        temp_env::with_var("XDG_CONFIG_HOME", Some(dir.path().to_str().unwrap()), || {
            let r = set_config_key("nodot", "value");
            assert!(r.is_err());
            assert!(matches!(r.unwrap_err(), ConfigError::UnknownKey { .. }));
        });
    }

    #[test]
    fn default_cache_path_under_xdg_cache_home() {
        let dir = tempfile::tempdir().unwrap();
        let path_str = dir.path().to_string_lossy().into_owned();
        temp_env::with_var("XDG_CACHE_HOME", Some(path_str.as_str()), || {
            let p = default_cache_path();
            assert!(p.to_string_lossy().contains(path_str.as_str()));
            assert!(p.ends_with("vlz-cache.redb"));
        });
    }

    #[test]
    fn default_ignore_path_under_xdg_data_home() {
        let dir = tempfile::tempdir().unwrap();
        let path_str = dir.path().to_string_lossy().into_owned();
        temp_env::with_var("XDG_DATA_HOME", Some(path_str.as_str()), || {
            let p = default_ignore_path();
            assert!(p.to_string_lossy().contains(path_str.as_str()));
            assert!(p.ends_with("vlz-ignore.redb"));
        });
    }

    #[test]
    fn default_cache_path_privileged_uses_var_cache() {
        set_mock_privileged(Some(true));
        let p = default_cache_path();
        set_mock_privileged(None);
        assert_eq!(p.to_string_lossy(), "/var/cache/verilyze/vlz-cache.redb");
    }

    #[test]
    fn default_ignore_path_privileged_uses_var_lib() {
        set_mock_privileged(Some(true));
        let p = default_ignore_path();
        set_mock_privileged(None);
        assert_eq!(p.to_string_lossy(), "/var/lib/verilyze/vlz-ignore.redb");
    }

    #[test]
    fn env_vars_read_correctly() {
        temp_env::with_vars(
            [
                ("VLZ_PARALLEL_QUERIES", Some("7")),
                ("VLZ_CACHE_DB", Some("/tmp/cache.redb")),
                ("VLZ_IGNORE_DB", Some("/tmp/ignore.redb")),
                ("VLZ_CACHE_TTL_SECS", Some("100")),
                ("VLZ_MIN_SCORE", Some("5.5")),
                ("VLZ_MIN_COUNT", Some("3")),
                ("VLZ_EXIT_CODE_ON_CVE", Some("86")),
                ("VLZ_FP_EXIT_CODE", Some("0")),
            ],
            || {
                assert_eq!(env_parallel(), Some(7));
                assert_eq!(
                    env_cache_db().as_ref().and_then(|p| p.to_str()),
                    Some("/tmp/cache.redb")
                );
                assert_eq!(
                    env_ignore_db().as_ref().and_then(|p| p.to_str()),
                    Some("/tmp/ignore.redb")
                );
                assert_eq!(env_cache_ttl_secs(), Some(100));
                assert_eq!(env_min_score(), Some(5.5));
                assert_eq!(env_min_count(), Some(3));
                assert_eq!(env_exit_code_on_cve(), Some(86));
                assert_eq!(env_fp_exit_code(), Some(0));
            },
        );
    }

    #[test]
    fn env_vars_unset_return_none() {
        temp_env::with_vars(
            [
                ("VLZ_PARALLEL_QUERIES", None::<&str>),
                ("VLZ_CACHE_TTL_SECS", None::<&str>),
            ],
            || {
                assert_eq!(env_parallel(), None);
                assert_eq!(env_cache_ttl_secs(), None);
            },
        );
    }

    #[test]
    fn user_relative_path_home_tilde() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path_str = f.path().to_string_lossy().into_owned();
        temp_env::with_var("HOME", Some(path_str.as_str()), || {
            std::fs::write(f.path(), "invalid {{{").unwrap();
            let r = load(
                Some(f.path().to_str().unwrap()),
                None, None, None, None, None, None, None, None,
                None, None, None,
                None, None, None, None,
                false, false,
                None, None, None, None,
                false,
                None, None, None,
            );
            assert!(r.is_err());
            let err = r.unwrap_err();
            assert!(err.to_string().contains("~"));
        });
    }

    #[test]
    fn user_relative_path_home_tilde_with_rest() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("verilyze").join("verilyze.conf");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "invalid {{{").unwrap();
        let home_str = dir.path().to_string_lossy().into_owned();
        temp_env::with_var("HOME", Some(home_str.as_str()), || {
            let r = load(
                Some(config_path.to_str().unwrap()),
                None, None, None, None, None, None, None, None,
                None, None, None,
                None, None, None, None,
                false, false,
                None, None, None, None,
                false,
                None, None, None,
            );
            assert!(r.is_err());
            let err = r.unwrap_err();
            assert!(err.to_string().contains("~/"));
        });
    }

    #[test]
    fn user_relative_path_no_home_uses_full_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("vlz.conf");
        std::fs::write(&config_path, "invalid {{{").unwrap();
        temp_env::with_var("HOME", None::<&str>, || {
            let r = load(
                Some(config_path.to_str().unwrap()),
                None, None, None, None, None, None, None, None,
                None, None, None,
                None, None, None, None,
                false, false,
                None, None, None, None,
                false,
                None, None, None,
            );
            assert!(r.is_err());
            let err = r.unwrap_err();
            assert!(err.to_string().contains(config_path.to_str().unwrap()));
        });
    }

    #[test]
    fn apply_file_config_all_fields_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("vlz.conf");
        let toml = r#"
cache_db = "/tmp/cache.redb"
ignore_db = "/tmp/ignore.redb"
parallel_queries = 5
cache_ttl_secs = 100
min_score = 7.5
min_count = 2
exit_code_on_cve = 86
fp_exit_code = 0
backoff_base_ms = 50
backoff_max_ms = 5000
max_retries = 3
[python]
regex = "^req\\.txt$"
"#;
        std::fs::write(&config_path, toml).unwrap();
        let path_str = config_path.to_string_lossy().into_owned();
        let cfg = load(
            Some(&path_str),
            None, None, None, None, None, None, None, None,
            None, None, None,
            None, None, None, None,
            false, false,
            None, None, None, None,
            false,
            None, None, None,
        )
        .unwrap();
        assert_eq!(cfg.cache_db.as_ref().unwrap().to_str(), Some("/tmp/cache.redb"));
        assert_eq!(cfg.ignore_db.as_ref().unwrap().to_str(), Some("/tmp/ignore.redb"));
        assert_eq!(cfg.parallel_queries, 5);
        assert_eq!(cfg.cache_ttl_secs, 100);
        assert_eq!(cfg.min_score, 7.5);
        assert_eq!(cfg.min_count, 2);
        assert_eq!(cfg.exit_code_on_cve, Some(86));
        assert_eq!(cfg.fp_exit_code, Some(0));
        assert_eq!(cfg.backoff_base_ms, 50);
        assert_eq!(cfg.backoff_max_ms, 5000);
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(cfg.language_regexes, vec![("python".to_string(), "^req\\.txt$".to_string())]);
    }

    #[test]
    fn apply_file_config_unknown_scalar_key_returns_error() {
        let r = parse_and_validate_toml("unknown_key = 1");
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConfigError::UnknownKey { .. }));
    }

    #[test]
    fn load_config_file_override_uses_given_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("custom.conf");
        std::fs::write(&config_path, "parallel_queries = 3").unwrap();
        let path_str = config_path.to_string_lossy().into_owned();
        let cfg = load(
            Some(&path_str),
            None, None, None, None, None, None, None, None,
            None, None, None,
            None, None, None, None,
            false, false,
            None, None, None, None,
            false,
            None, None, None,
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, 3);
        assert_eq!(cfg.config_file.as_ref().unwrap(), &config_path);
    }

    #[test]
    fn load_env_overrides_applied() {
        let cfg = load(
            None,
            Some(7),
            Some(PathBuf::from("/env/cache.redb")),
            Some(PathBuf::from("/env/ignore.redb")),
            Some(200),
            Some(6.0),
            Some(4),
            Some(90),
            Some(1),
            None,
            None,
            None,
            None, None, None, None,
            false, false,
            None, None, None, None,
            false,
            None, None, None,
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, 7);
        assert_eq!(cfg.cache_db.as_ref().unwrap().to_str(), Some("/env/cache.redb"));
        assert_eq!(cfg.ignore_db.as_ref().unwrap().to_str(), Some("/env/ignore.redb"));
        assert_eq!(cfg.cache_ttl_secs, 200);
        assert_eq!(cfg.min_score, 6.0);
        assert_eq!(cfg.min_count, 4);
        assert_eq!(cfg.exit_code_on_cve, Some(90));
        assert_eq!(cfg.fp_exit_code, Some(1));
    }

    #[test]
    fn load_cli_overrides_applied() {
        let cfg = load(
            None,
            None, None, None, None, None, None, None, None,
            None, None, None,
            Some(8),
            Some("/cli/cache.redb"),
            Some("/cli/ignore.redb"),
            Some(300),
            true, true,
            Some(5.0),
            Some(6),
            Some(88),
            Some(2),
            true,
            None, None, None,
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, 8);
        assert_eq!(cfg.cache_db.as_ref().unwrap().to_str(), Some("/cli/cache.redb"));
        assert_eq!(cfg.ignore_db.as_ref().unwrap().to_str(), Some("/cli/ignore.redb"));
        assert_eq!(cfg.cache_ttl_secs, 300);
        assert_eq!(cfg.offline, true);
        assert_eq!(cfg.benchmark, true);
        assert_eq!(cfg.min_score, 5.0);
        assert_eq!(cfg.min_count, 6);
        assert_eq!(cfg.exit_code_on_cve, Some(88));
        assert_eq!(cfg.fp_exit_code, Some(2));
        assert_eq!(cfg.package_manager_required, true);
    }

    #[test]
    fn load_backoff_config_from_env() {
        temp_env::with_vars(
            [
                ("VLZ_BACKOFF_BASE_MS", Some("200")),
                ("VLZ_BACKOFF_MAX_MS", Some("10000")),
                ("VLZ_MAX_RETRIES", Some("7")),
            ],
            || {
                let cfg = load(
                    None,
                    env_parallel(),
                    env_cache_db(),
                    env_ignore_db(),
                    env_cache_ttl_secs(),
                    env_min_score(),
                    env_min_count(),
                    env_exit_code_on_cve(),
                    env_fp_exit_code(),
                    env_backoff_base_ms(),
                    env_backoff_max_ms(),
                    env_max_retries(),
                    None, None, None, None,
                    false, false,
                    None, None, None, None,
                    false,
                    None, None, None,
                )
                .unwrap();
                assert_eq!(cfg.backoff_base_ms, 200);
                assert_eq!(cfg.backoff_max_ms, 10000);
                assert_eq!(cfg.max_retries, 7);
            },
        );
    }

    #[test]
    fn load_backoff_config_cli_overrides() {
        let cfg = load(
            None,
            None, None, None, None, None, None, None, None,
            Some(150),
            Some(8000),
            Some(4),
            None, None, None, None,
            false, false,
            None, None, None, None,
            false,
            Some(250),
            Some(15000),
            Some(6),
        )
        .unwrap();
        assert_eq!(cfg.backoff_base_ms, 250);
        assert_eq!(cfg.backoff_max_ms, 15000);
        assert_eq!(cfg.max_retries, 6);
    }

    #[test]
    fn set_config_key_config_path_is_directory_returns_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir(xdg.join("verilyze.conf")).unwrap();
        temp_env::with_var("XDG_CONFIG_HOME", Some(dir.path().join("xdg").to_str().unwrap()), || {
            let r = set_config_key("python.regex", "x");
            assert!(r.is_err());
            assert!(matches!(r.unwrap_err(), ConfigError::Io(_)));
        });
    }

    #[test]
    fn user_config_path_xdg_overrides_home() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path().join("xdg-config");
        std::fs::create_dir_all(xdg.join("verilyze")).unwrap();
        std::fs::write(xdg.join("verilyze").join("verilyze.conf"), "parallel_queries = 10").unwrap();
        temp_env::with_vars(
            [
                ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
                ("HOME", Some("/nonexistent")),
            ],
            || {
                let cfg = load(
                    None,
                    None, None, None, None, None, None, None, None,
                    None, None, None,
                    None, None, None, None,
                    false, false,
                    None, None, None, None,
                    false,
                    None, None, None,
                )
                .unwrap();
                assert_eq!(cfg.parallel_queries, 10);
            },
        );
    }

    #[test]
    fn user_config_path_home_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".config").join("verilyze")).unwrap();
        std::fs::write(home.join(".config").join("verilyze").join("verilyze.conf"), "parallel_queries = 42").unwrap();
        temp_env::with_var("XDG_CONFIG_HOME", None::<&str>, || {
            temp_env::with_var("HOME", Some(home.to_str().unwrap()), || {
                let cfg = load(
                    None,
                    None, None, None, None, None, None, None, None,
                    None, None, None,
                    None, None, None, None,
                    false, false,
                    None, None, None, None,
                    false,
                    None, None, None,
                )
                .unwrap();
                assert_eq!(cfg.parallel_queries, 42);
            });
        });
    }

    #[test]
    fn cache_home_fallback_when_no_xdg() {
        temp_env::with_vars(
            [
                ("XDG_CACHE_HOME", None::<&str>),
                ("HOME", Some("/fake/home")),
            ],
            || {
                let p = default_cache_path();
                assert!(p.to_string_lossy().contains(".cache"));
            },
        );
    }

    #[test]
    fn cache_home_fallback_when_no_xdg_and_no_home() {
        temp_env::with_vars(
            [
                ("XDG_CACHE_HOME", None::<&str>),
                ("HOME", None::<&str>),
            ],
            || {
                let p = default_cache_path();
                assert!(p.to_string_lossy().contains(".cache"));
            },
        );
    }

    #[test]
    fn data_home_fallback_when_no_xdg() {
        temp_env::with_vars(
            [
                ("XDG_DATA_HOME", None::<&str>),
                ("HOME", Some("/fake/home")),
            ],
            || {
                let p = default_ignore_path();
                assert!(p.to_string_lossy().contains(".local"));
            },
        );
    }

    #[test]
    fn data_home_fallback_when_no_xdg_and_no_home() {
        temp_env::with_vars(
            [
                ("XDG_DATA_HOME", None::<&str>),
                ("HOME", None::<&str>),
            ],
            || {
                let p = default_ignore_path();
                assert!(p.to_string_lossy().contains(".local"));
            },
        );
    }

    #[test]
    fn set_config_key_invalid_existing_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("verilyze.conf"), "invalid toml {{{").unwrap();
        temp_env::with_var("XDG_CONFIG_HOME", Some(dir.path().join("xdg").to_str().unwrap()), || {
            let r = set_config_key("python.regex", "x");
            assert!(r.is_err());
        });
    }

    #[test]
    fn set_config_key_create_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path().join("new").join("path");
        let config_path = xdg.join("verilyze").join("verilyze.conf");
        temp_env::with_var("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap()), || {
            let r = set_config_key("python.regex", "^test$");
            assert!(r.is_ok());
            assert!(config_path.exists());
            let content = std::fs::read_to_string(&config_path).unwrap();
            assert!(content.contains("^test$"));
        });
    }

    #[test]
    fn set_config_key_value_not_table_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("verilyze.conf"), "python = 42").unwrap();
        temp_env::with_var("XDG_CONFIG_HOME", Some(dir.path().join("xdg").to_str().unwrap()), || {
            let r = set_config_key("python.regex", "x");
            assert!(r.is_err());
            assert!(matches!(r.unwrap_err(), ConfigError::UnknownKey { .. }));
        });
    }
}
