// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Read;
use std::path::{Path, PathBuf};

use thiserror::Error;
pub use vlz_cve_client::{
    DEFAULT_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS,
    DEFAULT_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityMode {
    Off,
    TierB,
    BestAvailable,
}

pub const DEFAULT_REACHABILITY_MODE: ReachabilityMode =
    ReachabilityMode::TierB;

/// Per-CVSS-version severity threshold overrides (FR-013).
/// All fields are optional; when `None`, the corresponding default for that version is kept.
/// Used to carry both env-var and CLI overrides into `load()`.
#[derive(Debug, Clone, Default)]
pub struct SeverityOverrides {
    pub v2_critical: Option<f32>,
    pub v2_high: Option<f32>,
    pub v2_medium: Option<f32>,
    pub v2_low: Option<f32>,
    pub v3_critical: Option<f32>,
    pub v3_high: Option<f32>,
    pub v3_medium: Option<f32>,
    pub v3_low: Option<f32>,
    pub v4_critical: Option<f32>,
    pub v4_high: Option<f32>,
    pub v4_medium: Option<f32>,
    pub v4_low: Option<f32>,
}

/// Default parallel queries.
pub const DEFAULT_PARALLEL_QUERIES: usize = 10;

/// Default cache TTL in seconds (OP-009: 5 days).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 5 * 24 * 60 * 60;

/// Default directory names to skip during manifest discovery.
pub const DEFAULT_SCAN_EXCLUDE_DIRS: &[&str] = &[".git"];

/// Default backoff base in milliseconds (SEC-007).
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 100;

/// Default backoff max in milliseconds.
pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;

/// Default max retries for transient errors (NFR-005, SEC-007).
pub const DEFAULT_MAX_RETRIES: u32 = 5;

/// Maximum CVE provider HTTPS connect timeout in seconds (CFG-008).
pub const MAX_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS: u64 = 3600;

/// Maximum CVE provider HTTPS total request timeout in seconds (CFG-008).
pub const MAX_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS: u64 = 86_400;

#[derive(Debug, Clone)]
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
    /// Project ID for false-positive scoping (FR-015); when set, only FPs marked for this project or globally apply.
    pub project_id: Option<String>,
    /// Per-language manifest regex patterns (FR-006); order = first match wins.
    pub language_regexes: Vec<(String, String)>,
    /// Directory names to skip during manifest discovery.
    pub scan_exclude_dirs: Vec<String>,
    /// If true, exit 3 with hint when required package manager (e.g. pip) is not on PATH (FR-024).
    pub package_manager_required: bool,
    /// Backoff base delay in milliseconds (NFR-005, SEC-007, OP-010).
    pub backoff_base_ms: u64,
    /// Backoff maximum delay in milliseconds.
    pub backoff_max_ms: u64,
    /// Maximum retries for transient errors.
    pub max_retries: u32,
    /// CVE provider HTTPS connect timeout in seconds (OP-010, CFG-005).
    pub provider_http_connect_timeout_secs: u64,
    /// CVE provider HTTPS total request timeout in seconds (OP-010).
    pub provider_http_request_timeout_secs: u64,
    /// PEM file of CRLs for Linux TLS revocation checking (SEC-021); `None` = default verifier.
    pub tls_crl_bundle: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    /// Configurable CVSS severity thresholds per version (FR-013).
    pub severity: vlz_report::SeverityConfig,
    pub reachability_mode: ReachabilityMode,
}

impl Default for EffectiveConfig {
    fn default() -> Self {
        Self {
            cache_db: None,
            ignore_db: None,
            parallel_queries: 0,
            cache_ttl_secs: 0,
            offline: false,
            benchmark: false,
            min_score: 0.0,
            min_count: 0,
            exit_code_on_cve: None,
            fp_exit_code: None,
            project_id: None,
            language_regexes: Vec::new(),
            scan_exclude_dirs: DEFAULT_SCAN_EXCLUDE_DIRS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            package_manager_required: false,
            backoff_base_ms: 0,
            backoff_max_ms: 0,
            max_retries: 0,
            provider_http_connect_timeout_secs: 0,
            provider_http_request_timeout_secs: 0,
            tls_crl_bundle: None,
            config_file: None,
            severity: vlz_report::SeverityConfig::default(),
            reachability_mode: DEFAULT_REACHABILITY_MODE,
        }
    }
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
    #[serde(rename = "project_id")]
    project_id: Option<String>,
    #[serde(rename = "backoff_base_ms")]
    backoff_base_ms: Option<u64>,
    #[serde(rename = "backoff_max_ms")]
    backoff_max_ms: Option<u64>,
    #[serde(rename = "max_retries")]
    max_retries: Option<u32>,
    #[serde(rename = "provider_http_connect_timeout_secs")]
    provider_http_connect_timeout_secs: Option<u64>,
    #[serde(rename = "provider_http_request_timeout_secs")]
    provider_http_request_timeout_secs: Option<u64>,
    #[serde(rename = "tls_crl_bundle")]
    tls_crl_bundle: Option<String>,
    #[serde(rename = "scan_exclude_dirs")]
    scan_exclude_dirs: Option<Vec<String>>,
    #[serde(rename = "reachability_mode")]
    reachability_mode: Option<String>,
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

    #[error("Invalid CVE provider HTTP timeouts: {message}")]
    InvalidProviderHttpTimeouts { message: String },

    #[error("Invalid TLS CRL bundle path: {message}")]
    InvalidTlsCrlBundle { message: String },

    #[error("Invalid reachability mode '{value}' (from {origin})")]
    InvalidReachabilityMode { value: String, origin: String },

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
    "project_id",
    "backoff_base_ms",
    "backoff_max_ms",
    "max_retries",
    "provider_http_connect_timeout_secs",
    "provider_http_request_timeout_secs",
    "tls_crl_bundle",
    "scan_exclude_dirs",
    "reachability_mode",
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
    let parsed: FileConfig =
        toml::from_str(raw).map_err(|e| ConfigError::InvalidToml {
            path: path.to_path_buf(),
            path_display: user_relative_path(path),
            message: e.to_string(),
        })?;
    // SEC-006: reject unknown keys. Allow only known scalars and [lang] tables.
    // Use toml::from_str (same as FileConfig) so we get the same parse behavior.
    if let Ok(value) = toml::from_str::<toml::Value>(raw)
        && let Some(t) = value.as_table()
    {
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
    if let Some(id) = parsed.project_id {
        cfg.project_id = Some(id);
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
    if let Some(n) = parsed.provider_http_connect_timeout_secs {
        cfg.provider_http_connect_timeout_secs = n;
    }
    if let Some(n) = parsed.provider_http_request_timeout_secs {
        cfg.provider_http_request_timeout_secs = n;
    }
    if let Some(p) = parsed.tls_crl_bundle {
        cfg.tls_crl_bundle = Some(PathBuf::from(p));
    }
    if let Some(dirs) = parsed.scan_exclude_dirs {
        cfg.scan_exclude_dirs = dirs;
    }
    if let Some(mode) = parsed.reachability_mode {
        cfg.reachability_mode = parse_reachability_mode(&mode, source)?;
    }
    if extract_language_regexes {
        cfg.language_regexes.clear();
        if let Ok(value) = toml::from_str::<toml::Value>(raw)
            && let Some(t) = value.as_table()
        {
            for (lang, table) in t {
                if let Some(tbl) = table.as_table()
                    && let Some(r) = tbl.get("regex").and_then(|v| v.as_str())
                {
                    cfg.language_regexes.push((lang.clone(), r.to_string()));
                }
            }
        }
    }
    // FR-013: parse [severity.v2], [severity.v3], [severity.v4] sections.
    if let Ok(value) = toml::from_str::<toml::Value>(raw)
        && let Some(t) = value.as_table()
        && let Some(sev_val) = t.get("severity")
        && let Some(sev) = sev_val.as_table()
    {
        apply_toml_severity_table(sev, "v2", &mut cfg.severity.v2);
        apply_toml_severity_table(sev, "v3", &mut cfg.severity.v3);
        apply_toml_severity_table(sev, "v4", &mut cfg.severity.v4);
    }
    let _ = source;
    Ok(())
}

/// Apply TOML severity sub-table (e.g. `[severity.v3]`) to the given thresholds (FR-013).
fn apply_toml_severity_table(
    sev: &toml::Table,
    version_key: &str,
    thresholds: &mut vlz_report::SeverityThresholds,
) {
    if let Some(tbl) = sev.get(version_key).and_then(|v| v.as_table()) {
        if let Some(v) = tbl.get("critical_min").and_then(|v| v.as_float()) {
            thresholds.critical_min = v as f32;
        }
        if let Some(v) = tbl.get("high_min").and_then(|v| v.as_float()) {
            thresholds.high_min = v as f32;
        }
        if let Some(v) = tbl.get("medium_min").and_then(|v| v.as_float()) {
            thresholds.medium_min = v as f32;
        }
        if let Some(v) = tbl.get("low_min").and_then(|v| v.as_float()) {
            thresholds.low_min = v as f32;
        }
    }
}

pub fn parse_reachability_mode(
    value: &str,
    origin: &str,
) -> Result<ReachabilityMode, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(ReachabilityMode::Off),
        "tier-b" => Ok(ReachabilityMode::TierB),
        "best-available" => Ok(ReachabilityMode::BestAvailable),
        _ => Err(ConfigError::InvalidReachabilityMode {
            value: value.to_string(),
            origin: origin.to_string(),
        }),
    }
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
        apply_file_config_inner(
            cfg,
            raw,
            path,
            source,
            extract_language_regexes,
        )
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
        const { std::cell::RefCell::new(None) };
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
                if let Some(stripped) = line.strip_prefix("Uid:") {
                    let mut fields = stripped.split_whitespace();
                    let _real = fields.next();
                    let effective =
                        fields.next().and_then(|s| s.parse::<u32>().ok());
                    return effective == Some(0);
                }
            }
        }
        false
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

/// Base directory for security-sensitive temporary data (e.g. ephemeral venvs).
/// Prefers XDG_RUNTIME_DIR (per-user, not world-writable), then TMPDIR, then
/// std::env::temp_dir(). Use with tempfile::tempdir_in() for atomic creation.
pub fn secure_temp_base() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("TMPDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn validate_provider_http_timeouts(
    connect_secs: u64,
    request_secs: u64,
) -> Result<(), ConfigError> {
    if connect_secs < 1 {
        return Err(ConfigError::InvalidProviderHttpTimeouts {
            message: format!(
                "provider_http_connect_timeout_secs must be at least 1; got {}",
                connect_secs
            ),
        });
    }
    if request_secs < 1 {
        return Err(ConfigError::InvalidProviderHttpTimeouts {
            message: format!(
                "provider_http_request_timeout_secs must be at least 1; got {}",
                request_secs
            ),
        });
    }
    if connect_secs > MAX_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS {
        return Err(ConfigError::InvalidProviderHttpTimeouts {
            message: format!(
                "provider_http_connect_timeout_secs must be at most {}; got {}",
                MAX_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS, connect_secs
            ),
        });
    }
    if request_secs > MAX_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS {
        return Err(ConfigError::InvalidProviderHttpTimeouts {
            message: format!(
                "provider_http_request_timeout_secs must be at most {}; got {}",
                MAX_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS, request_secs
            ),
        });
    }
    if request_secs < connect_secs {
        return Err(ConfigError::InvalidProviderHttpTimeouts {
            message: format!(
                "provider_http_request_timeout_secs ({}) must be >= provider_http_connect_timeout_secs ({})",
                request_secs, connect_secs
            ),
        });
    }
    Ok(())
}

fn validate_tls_crl_bundle_readable(path: &Path) -> Result<(), ConfigError> {
    let meta = std::fs::metadata(path).map_err(|e| {
        ConfigError::InvalidTlsCrlBundle {
            message: format!("{}: {}", user_relative_path(path), e),
        }
    })?;
    if !meta.is_file() {
        return Err(ConfigError::InvalidTlsCrlBundle {
            message: format!(
                "{} is not a regular file",
                user_relative_path(path)
            ),
        });
    }
    let mut f = std::fs::File::open(path).map_err(|e| {
        ConfigError::InvalidTlsCrlBundle {
            message: format!("{}: {}", user_relative_path(path), e),
        }
    })?;
    let mut buf = [0_u8; 1];
    f.read_exact(&mut buf)
        .map_err(|e| ConfigError::InvalidTlsCrlBundle {
            message: format!("{}: {}", user_relative_path(path), e),
        })?;
    Ok(())
}

/// Build effective config: defaults, then system file, user file, -c file, env, CLI.
/// Validates parallel_queries <= MAX_PARALLEL_QUERIES (FR-012).
#[allow(clippy::too_many_arguments)]
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
    env_project_id: Option<String>,
    env_backoff_base_ms: Option<u64>,
    env_backoff_max_ms: Option<u64>,
    env_max_retries: Option<u32>,
    env_provider_http_connect_timeout_secs: Option<u64>,
    env_provider_http_request_timeout_secs: Option<u64>,
    env_tls_crl_bundle: Option<PathBuf>,
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
    cli_project_id: Option<String>,
    cli_package_manager_required: bool,
    cli_backoff_base_ms: Option<u64>,
    cli_backoff_max_ms: Option<u64>,
    cli_max_retries: Option<u32>,
    cli_provider_http_connect_timeout_secs: Option<u64>,
    cli_provider_http_request_timeout_secs: Option<u64>,
    cli_tls_crl_bundle: Option<String>,
    // FR-013, CFG-005: severity threshold overrides from environment variables.
    env_severity: SeverityOverrides,
    // FR-013, CFG-006: severity threshold overrides from CLI flags; takes precedence over env.
    cli_severity: SeverityOverrides,
) -> Result<EffectiveConfig, ConfigError> {
    load_with_reachability_overrides(
        config_file_override,
        env_parallel,
        env_cache_db,
        env_ignore_db,
        env_cache_ttl_secs,
        env_min_score,
        env_min_count,
        env_exit_code_on_cve,
        env_fp_exit_code,
        env_project_id,
        env_backoff_base_ms,
        env_backoff_max_ms,
        env_max_retries,
        env_provider_http_connect_timeout_secs,
        env_provider_http_request_timeout_secs,
        env_tls_crl_bundle,
        cli_parallel,
        cli_cache_db,
        cli_ignore_db,
        cli_cache_ttl_secs,
        cli_offline,
        cli_benchmark,
        cli_min_score,
        cli_min_count,
        cli_exit_code_on_cve,
        cli_fp_exit_code,
        cli_project_id,
        cli_package_manager_required,
        cli_backoff_base_ms,
        cli_backoff_max_ms,
        cli_max_retries,
        cli_provider_http_connect_timeout_secs,
        cli_provider_http_request_timeout_secs,
        cli_tls_crl_bundle,
        None,
        None,
        env_severity,
        cli_severity,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn load_with_reachability_overrides(
    config_file_override: Option<&str>,
    env_parallel: Option<usize>,
    env_cache_db: Option<PathBuf>,
    env_ignore_db: Option<PathBuf>,
    env_cache_ttl_secs: Option<u64>,
    env_min_score: Option<f32>,
    env_min_count: Option<usize>,
    env_exit_code_on_cve: Option<u8>,
    env_fp_exit_code: Option<u8>,
    env_project_id: Option<String>,
    env_backoff_base_ms: Option<u64>,
    env_backoff_max_ms: Option<u64>,
    env_max_retries: Option<u32>,
    env_provider_http_connect_timeout_secs: Option<u64>,
    env_provider_http_request_timeout_secs: Option<u64>,
    env_tls_crl_bundle: Option<PathBuf>,
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
    cli_project_id: Option<String>,
    cli_package_manager_required: bool,
    cli_backoff_base_ms: Option<u64>,
    cli_backoff_max_ms: Option<u64>,
    cli_max_retries: Option<u32>,
    cli_provider_http_connect_timeout_secs: Option<u64>,
    cli_provider_http_request_timeout_secs: Option<u64>,
    cli_tls_crl_bundle: Option<String>,
    env_reachability_mode: Option<ReachabilityMode>,
    cli_reachability_mode: Option<ReachabilityMode>,
    // FR-013, CFG-005: severity threshold overrides from environment variables.
    env_severity: SeverityOverrides,
    // FR-013, CFG-006: severity threshold overrides from CLI flags; takes precedence over env.
    cli_severity: SeverityOverrides,
) -> Result<EffectiveConfig, ConfigError> {
    let mut cfg = EffectiveConfig {
        parallel_queries: DEFAULT_PARALLEL_QUERIES,
        cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
        backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
        backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
        max_retries: DEFAULT_MAX_RETRIES,
        provider_http_connect_timeout_secs:
            DEFAULT_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS,
        provider_http_request_timeout_secs:
            DEFAULT_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS,
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
        apply_file_config(
            &mut cfg,
            raw.as_str(),
            &path_to_load,
            "user",
            true,
        )?;
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
    if let Some(id) = env_project_id {
        cfg.project_id = Some(id);
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
    if let Some(n) = env_provider_http_connect_timeout_secs {
        cfg.provider_http_connect_timeout_secs = n;
    }
    if let Some(n) = env_provider_http_request_timeout_secs {
        cfg.provider_http_request_timeout_secs = n;
    }
    if let Some(p) = env_tls_crl_bundle {
        cfg.tls_crl_bundle = Some(p);
    }
    if let Some(dirs) = env_scan_exclude_dirs() {
        cfg.scan_exclude_dirs = dirs;
    }
    if let Some(mode) = env_reachability_mode {
        cfg.reachability_mode = mode;
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
    if let Some(id) = cli_project_id {
        cfg.project_id = Some(id);
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
    if let Some(n) = cli_provider_http_connect_timeout_secs {
        cfg.provider_http_connect_timeout_secs = n;
    }
    if let Some(n) = cli_provider_http_request_timeout_secs {
        cfg.provider_http_request_timeout_secs = n;
    }
    if let Some(p) = cli_tls_crl_bundle {
        cfg.tls_crl_bundle = Some(PathBuf::from(p));
    }
    if let Some(mode) = cli_reachability_mode {
        cfg.reachability_mode = mode;
    }

    validate_provider_http_timeouts(
        cfg.provider_http_connect_timeout_secs,
        cfg.provider_http_request_timeout_secs,
    )?;

    if let Some(ref p) = cfg.tls_crl_bundle {
        validate_tls_crl_bundle_readable(p)?;
    }

    if cfg.parallel_queries > MAX_PARALLEL_QUERIES {
        return Err(ConfigError::ParallelTooHigh {
            value: cfg.parallel_queries,
            max: MAX_PARALLEL_QUERIES,
        });
    }

    // FR-013: apply severity threshold overrides (env first, then CLI).
    apply_severity_overrides(&mut cfg.severity, &env_severity);
    apply_severity_overrides(&mut cfg.severity, &cli_severity);

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

/// Read VLZ_PROJECT_ID (FR-015, CFG-005); scopes false-positive filtering.
pub fn env_project_id() -> Option<String> {
    std::env::var("VLZ_PROJECT_ID").ok()
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

/// Read `VLZ_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS` (OP-010, CFG-005).
pub fn env_provider_http_connect_timeout_secs() -> Option<u64> {
    std::env::var("VLZ_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Read `VLZ_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS` (OP-010, CFG-005).
pub fn env_provider_http_request_timeout_secs() -> Option<u64> {
    std::env::var("VLZ_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Read `VLZ_TLS_CRL_BUNDLE` (SEC-021, CFG-005): PEM CRL bundle path (Linux only).
pub fn env_tls_crl_bundle() -> Option<PathBuf> {
    std::env::var_os("VLZ_TLS_CRL_BUNDLE").map(PathBuf::from)
}

/// Read `VLZ_REACHABILITY_MODE`.
pub fn env_reachability_mode() -> Option<ReachabilityMode> {
    std::env::var("VLZ_REACHABILITY_MODE")
        .ok()
        .and_then(|v| parse_reachability_mode(&v, "environment").ok())
}

/// Read `VLZ_SCAN_EXCLUDE_DIRS` as comma-separated directory names.
pub fn env_scan_exclude_dirs() -> Option<Vec<String>> {
    std::env::var("VLZ_SCAN_EXCLUDE_DIRS").ok().map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

/// Read all VLZ_SEVERITY_* env vars and return a `SeverityOverrides` (FR-013, CFG-005).
pub fn env_severity_overrides() -> SeverityOverrides {
    fn read_f32(name: &str) -> Option<f32> {
        std::env::var(name).ok().and_then(|s| s.parse().ok())
    }
    SeverityOverrides {
        v2_critical: read_f32("VLZ_SEVERITY_V2_CRITICAL_MIN"),
        v2_high: read_f32("VLZ_SEVERITY_V2_HIGH_MIN"),
        v2_medium: read_f32("VLZ_SEVERITY_V2_MEDIUM_MIN"),
        v2_low: read_f32("VLZ_SEVERITY_V2_LOW_MIN"),
        v3_critical: read_f32("VLZ_SEVERITY_V3_CRITICAL_MIN"),
        v3_high: read_f32("VLZ_SEVERITY_V3_HIGH_MIN"),
        v3_medium: read_f32("VLZ_SEVERITY_V3_MEDIUM_MIN"),
        v3_low: read_f32("VLZ_SEVERITY_V3_LOW_MIN"),
        v4_critical: read_f32("VLZ_SEVERITY_V4_CRITICAL_MIN"),
        v4_high: read_f32("VLZ_SEVERITY_V4_HIGH_MIN"),
        v4_medium: read_f32("VLZ_SEVERITY_V4_MEDIUM_MIN"),
        v4_low: read_f32("VLZ_SEVERITY_V4_LOW_MIN"),
    }
}

/// Apply a `SeverityOverrides` to a `SeverityConfig` (FR-013).
/// Each `Some` value overwrites the corresponding threshold; `None` keeps the existing value.
pub fn apply_severity_overrides(
    config: &mut vlz_report::SeverityConfig,
    overrides: &SeverityOverrides,
) {
    macro_rules! apply {
        ($field:expr, $opt:expr) => {
            if let Some(v) = $opt {
                $field = v;
            }
        };
    }
    apply!(config.v2.critical_min, overrides.v2_critical);
    apply!(config.v2.high_min, overrides.v2_high);
    apply!(config.v2.medium_min, overrides.v2_medium);
    apply!(config.v2.low_min, overrides.v2_low);
    apply!(config.v3.critical_min, overrides.v3_critical);
    apply!(config.v3.high_min, overrides.v3_high);
    apply!(config.v3.medium_min, overrides.v3_medium);
    apply!(config.v3.low_min, overrides.v3_low);
    apply!(config.v4.critical_min, overrides.v4_critical);
    apply!(config.v4.high_min, overrides.v4_high);
    apply!(config.v4.medium_min, overrides.v4_medium);
    apply!(config.v4.low_min, overrides.v4_low);
}

/// Set a config key (e.g. python.regex) in the given config file path (FR-006).
fn set_config_key_in_path(
    path: &Path,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }
    let raw = load_file_opt(path)?.unwrap_or_else(String::new);
    // toml 1.0: Value::FromStr parses single values; use Table for documents.
    let mut root: toml::Table = if raw.trim().is_empty() {
        toml::Table::new()
    } else {
        toml::from_str(&raw).map_err(|e: toml::de::Error| {
            ConfigError::InvalidToml {
                path: path.to_path_buf(),
                path_display: user_relative_path(path),
                message: e.to_string(),
            }
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
    let inner =
        entry
            .as_table_mut()
            .ok_or_else(|| ConfigError::UnknownKey {
                key: key.to_string(),
                origin: "config set".to_string(),
            })?;
    inner.insert(sub_key.to_string(), toml::Value::String(value.to_string()));
    let out = toml::to_string_pretty(&root).map_err(|e| {
        ConfigError::InvalidToml {
            path: path.to_path_buf(),
            path_display: user_relative_path(path),
            message: e.to_string(),
        }
    })?;
    std::fs::write(path, out)?;
    Ok(())
}

/// Set a config key (e.g. python.regex) in the user config file (FR-006).
pub fn set_config_key(key: &str, value: &str) -> Result<(), ConfigError> {
    let path = user_config_path();
    set_config_key_in_path(&path, key, value)
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
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, DEFAULT_PARALLEL_QUERIES);
        assert_eq!(cfg.cache_ttl_secs, DEFAULT_CACHE_TTL_SECS);
        assert_eq!(cfg.backoff_base_ms, DEFAULT_BACKOFF_BASE_MS);
        assert_eq!(cfg.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(
            cfg.provider_http_connect_timeout_secs,
            DEFAULT_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS
        );
        assert_eq!(
            cfg.provider_http_request_timeout_secs,
            DEFAULT_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS
        );
    }

    #[test]
    fn load_rejects_missing_tls_crl_bundle_sec021() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("verilyze.conf");
        std::fs::write(
            &conf,
            "tls_crl_bundle = \"/no/such/crl-bundle.pem\"\n",
        )
        .unwrap();
        let path_str = conf.to_string_lossy().into_owned();
        let r = load(
            Some(path_str.as_str()),
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        );
        assert!(matches!(r, Err(ConfigError::InvalidTlsCrlBundle { .. })));
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
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
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
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(dir.path().to_str().unwrap()),
            || {
                let r = set_config_key("nodot", "value");
                assert!(r.is_err());
                assert!(matches!(
                    r.unwrap_err(),
                    ConfigError::UnknownKey { .. }
                ));
            },
        );
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
    fn env_scan_exclude_dirs_parses_csv() {
        temp_env::with_var(
            "VLZ_SCAN_EXCLUDE_DIRS",
            Some(".git, node_modules ,target"),
            || {
                assert_eq!(
                    env_scan_exclude_dirs(),
                    Some(vec![
                        ".git".to_string(),
                        "node_modules".to_string(),
                        "target".to_string()
                    ])
                );
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
                None,
                None,
                None,
                false,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                None,
                Default::default(),
                Default::default(),
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
                None,
                None,
                None,
                false,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                None,
                Default::default(),
                Default::default(),
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
                None,
                None,
                None,
                false,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                None,
                Default::default(),
                Default::default(),
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
scan_exclude_dirs = [".git", "target"]
[python]
regex = "^req\\.txt$"
"#;
        std::fs::write(&config_path, toml).unwrap();
        let path_str = config_path.to_string_lossy().into_owned();
        let cfg = load(
            Some(&path_str),
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            cfg.cache_db.as_ref().unwrap().to_str(),
            Some("/tmp/cache.redb")
        );
        assert_eq!(
            cfg.ignore_db.as_ref().unwrap().to_str(),
            Some("/tmp/ignore.redb")
        );
        assert_eq!(cfg.parallel_queries, 5);
        assert_eq!(cfg.cache_ttl_secs, 100);
        assert_eq!(cfg.min_score, 7.5);
        assert_eq!(cfg.min_count, 2);
        assert_eq!(cfg.exit_code_on_cve, Some(86));
        assert_eq!(cfg.fp_exit_code, Some(0));
        assert_eq!(cfg.backoff_base_ms, 50);
        assert_eq!(cfg.backoff_max_ms, 5000);
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(
            cfg.scan_exclude_dirs,
            vec![".git".to_string(), "target".to_string()]
        );
        assert_eq!(
            cfg.language_regexes,
            vec![("python".to_string(), "^req\\.txt$".to_string())]
        );
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
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
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, 7);
        assert_eq!(
            cfg.cache_db.as_ref().unwrap().to_str(),
            Some("/env/cache.redb")
        );
        assert_eq!(
            cfg.ignore_db.as_ref().unwrap().to_str(),
            Some("/env/ignore.redb")
        );
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
            Some(8),
            Some("/cli/cache.redb"),
            Some("/cli/ignore.redb"),
            Some(300),
            true,
            true,
            Some(5.0),
            Some(6),
            Some(88),
            Some(2),
            Some("myproj".to_string()),
            true,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(cfg.parallel_queries, 8);
        assert_eq!(
            cfg.cache_db.as_ref().unwrap().to_str(),
            Some("/cli/cache.redb")
        );
        assert_eq!(
            cfg.ignore_db.as_ref().unwrap().to_str(),
            Some("/cli/ignore.redb")
        );
        assert_eq!(cfg.cache_ttl_secs, 300);
        assert!(cfg.offline);
        assert!(cfg.benchmark);
        assert_eq!(cfg.min_score, 5.0);
        assert_eq!(cfg.min_count, 6);
        assert_eq!(cfg.exit_code_on_cve, Some(88));
        assert_eq!(cfg.fp_exit_code, Some(2));
        assert_eq!(cfg.project_id, Some("myproj".to_string()));
        assert!(cfg.package_manager_required);
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
                    env_project_id(),
                    env_backoff_base_ms(),
                    env_backoff_max_ms(),
                    env_max_retries(),
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
                    None,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Default::default(),
                    Default::default(),
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
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            // env_project_id
            Some(150),
            Some(8000),
            Some(4),
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
            None,
            false,
            Some(250),
            Some(15000),
            Some(6),
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(cfg.backoff_base_ms, 250);
        assert_eq!(cfg.backoff_max_ms, 15000);
        assert_eq!(cfg.max_retries, 6);
    }

    #[test]
    fn load_provider_http_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vlz.conf");
        std::fs::write(
            &path,
            "provider_http_connect_timeout_secs = 25\nprovider_http_request_timeout_secs = 90\n",
        )
        .unwrap();
        let path_str = path.to_string_lossy().into_owned();
        let cfg = load(
            Some(path_str.as_str()),
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(cfg.provider_http_connect_timeout_secs, 25);
        assert_eq!(cfg.provider_http_request_timeout_secs, 90);
    }

    #[test]
    fn load_provider_http_env_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vlz.conf");
        std::fs::write(
            &path,
            "provider_http_connect_timeout_secs = 10\nprovider_http_request_timeout_secs = 200\n",
        )
        .unwrap();
        let path_str = path.to_string_lossy().into_owned();
        temp_env::with_vars(
            [
                ("VLZ_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS", Some("44")),
                ("VLZ_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS", Some("300")),
            ],
            || {
                let cfg = load(
                    Some(path_str.as_str()),
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
                    env_provider_http_connect_timeout_secs(),
                    env_provider_http_request_timeout_secs(),
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
                    None,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Default::default(),
                    Default::default(),
                )
                .unwrap();
                assert_eq!(cfg.provider_http_connect_timeout_secs, 44);
                assert_eq!(cfg.provider_http_request_timeout_secs, 300);
            },
        );
    }

    #[test]
    fn load_provider_http_cli_overrides_file_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vlz.conf");
        std::fs::write(
            &path,
            "provider_http_connect_timeout_secs = 10\nprovider_http_request_timeout_secs = 100\n",
        )
        .unwrap();
        let path_str = path.to_string_lossy().into_owned();
        temp_env::with_vars(
            [
                ("VLZ_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS", Some("30")),
                ("VLZ_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS", Some("150")),
            ],
            || {
                let cfg = load(
                    Some(path_str.as_str()),
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
                    env_provider_http_connect_timeout_secs(),
                    env_provider_http_request_timeout_secs(),
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
                    None,
                    false,
                    None,
                    None,
                    None,
                    Some(50),
                    Some(250),
                    None,
                    Default::default(),
                    Default::default(),
                )
                .unwrap();
                assert_eq!(cfg.provider_http_connect_timeout_secs, 50);
                assert_eq!(cfg.provider_http_request_timeout_secs, 250);
            },
        );
    }

    #[test]
    fn load_provider_http_zero_connect_fails_cfg008() {
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
            None,
            false,
            None,
            None,
            None,
            Some(0),
            Some(60),
            None,
            Default::default(),
            Default::default(),
        );
        assert!(matches!(
            r,
            Err(ConfigError::InvalidProviderHttpTimeouts { .. })
        ));
    }

    #[test]
    fn load_provider_http_request_below_connect_fails_cfg008() {
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
            None,
            false,
            None,
            None,
            None,
            Some(120),
            Some(30),
            None,
            Default::default(),
            Default::default(),
        );
        assert!(matches!(
            r,
            Err(ConfigError::InvalidProviderHttpTimeouts { .. })
        ));
    }

    #[test]
    fn set_config_key_config_path_is_directory_returns_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir(xdg.join("verilyze.conf")).unwrap();
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(dir.path().join("xdg").to_str().unwrap()),
            || {
                let r = set_config_key("python.regex", "x");
                assert!(r.is_err());
                assert!(matches!(r.unwrap_err(), ConfigError::Io(_)));
            },
        );
    }

    #[test]
    fn user_config_path_xdg_overrides_home() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path().join("xdg-config");
        std::fs::create_dir_all(xdg.join("verilyze")).unwrap();
        std::fs::write(
            xdg.join("verilyze").join("verilyze.conf"),
            "parallel_queries = 10",
        )
        .unwrap();
        temp_env::with_vars(
            [
                ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
                ("HOME", Some("/nonexistent")),
            ],
            || {
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
                    None,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Default::default(),
                    Default::default(),
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
        std::fs::create_dir_all(home.join(".config").join("verilyze"))
            .unwrap();
        std::fs::write(
            home.join(".config").join("verilyze").join("verilyze.conf"),
            "parallel_queries = 42",
        )
        .unwrap();
        temp_env::with_var("XDG_CONFIG_HOME", None::<&str>, || {
            temp_env::with_var("HOME", Some(home.to_str().unwrap()), || {
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
                    None,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Default::default(),
                    Default::default(),
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
            [("XDG_CACHE_HOME", None::<&str>), ("HOME", None::<&str>)],
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
    fn secure_temp_base_prefers_xdg_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path_str = dir.path().to_path_buf();
        temp_env::with_var(
            "XDG_RUNTIME_DIR",
            Some(path_str.as_os_str()),
            || {
                temp_env::with_var(
                    "TMPDIR",
                    Some(path_str.as_os_str()),
                    || {
                        let p = secure_temp_base();
                        assert_eq!(p, path_str);
                    },
                );
            },
        );
    }

    #[test]
    fn secure_temp_base_falls_back_to_tmpdir_when_no_xdg_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let path_str = dir.path().to_path_buf();
        temp_env::with_var("XDG_RUNTIME_DIR", None::<&str>, || {
            temp_env::with_var("TMPDIR", Some(path_str.as_os_str()), || {
                let p = secure_temp_base();
                assert_eq!(p, path_str);
            });
        });
    }

    #[test]
    fn secure_temp_base_falls_back_to_temp_dir_when_no_xdg_or_tmpdir() {
        temp_env::with_vars(
            [("XDG_RUNTIME_DIR", None::<&str>), ("TMPDIR", None::<&str>)],
            || {
                let p = secure_temp_base();
                assert!(!p.as_os_str().is_empty());
            },
        );
    }

    #[test]
    fn data_home_fallback_when_no_xdg_and_no_home() {
        temp_env::with_vars(
            [("XDG_DATA_HOME", None::<&str>), ("HOME", None::<&str>)],
            || {
                let p = default_ignore_path();
                assert!(p.to_string_lossy().contains(".local"));
            },
        );
    }

    #[test]
    fn set_config_key_invalid_existing_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("verilyze.conf");
        std::fs::write(&config_path, "invalid toml {{{").unwrap();
        let r = set_config_key_in_path(&config_path, "python.regex", "x");
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConfigError::InvalidToml { .. }));
    }

    #[test]
    fn set_config_key_create_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path().join("new").join("path");
        let config_path = xdg.join("verilyze").join("verilyze.conf");
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(xdg.to_str().unwrap()),
            || {
                let r = set_config_key("python.regex", "^test$");
                assert!(r.is_ok());
                assert!(config_path.exists());
                let content = std::fs::read_to_string(&config_path).unwrap();
                assert!(content.contains("^test$"));
            },
        );
    }

    #[test]
    fn set_config_key_value_not_table_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("verilyze.conf"), "python = 42")
            .unwrap();
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(dir.path().join("xdg").to_str().unwrap()),
            || {
                let r = set_config_key("python.regex", "x");
                assert!(r.is_err());
                assert!(matches!(
                    r.unwrap_err(),
                    ConfigError::UnknownKey { .. }
                ));
            },
        );
    }

    // FR-013: severity threshold configuration tests

    #[test]
    fn severity_defaults_match_vlz_report_defaults() {
        // EffectiveConfig.severity defaults must match SeverityConfig::default().
        // Use an empty temp dir for XDG_CONFIG_HOME to avoid picking up the real user config.
        let dir = tempfile::tempdir().unwrap();
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(dir.path().to_str().unwrap()),
            || {
                let cfg = load_no_severity(None);
                assert_eq!(cfg.severity.v3.critical_min, 9.0);
                assert_eq!(cfg.severity.v3.high_min, 7.0);
                assert_eq!(cfg.severity.v3.medium_min, 4.0);
                assert_eq!(cfg.severity.v3.low_min, 0.1);
            },
        );
    }

    #[test]
    fn severity_v3_critical_min_from_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("verilyze.conf"),
            "[severity.v3]\ncritical_min = 8.5\n",
        )
        .unwrap();
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(dir.path().join("xdg").to_str().unwrap()),
            || {
                let cfg = load_no_severity(None);
                assert_eq!(cfg.severity.v3.critical_min, 8.5);
                // other thresholds unchanged
                assert_eq!(cfg.severity.v3.high_min, 7.0);
            },
        );
    }

    #[test]
    fn severity_env_var_overrides_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("verilyze.conf"),
            "[severity.v3]\ncritical_min = 8.5\n",
        )
        .unwrap();
        temp_env::with_vars(
            [
                (
                    "XDG_CONFIG_HOME",
                    Some(dir.path().join("xdg").to_str().unwrap()),
                ),
                ("VLZ_SEVERITY_V3_CRITICAL_MIN", Some("8.0")),
            ],
            || {
                let env_sev = env_severity_overrides();
                let cfg = load_with_severity(
                    None,
                    env_sev,
                    SeverityOverrides::default(),
                );
                assert_eq!(cfg.severity.v3.critical_min, 8.0);
            },
        );
    }

    #[test]
    fn severity_cli_overrides_env_and_file() {
        let dir = tempfile::tempdir().unwrap();
        temp_env::with_vars(
            [
                ("XDG_CONFIG_HOME", Some(dir.path().to_str().unwrap())),
                ("VLZ_SEVERITY_V3_HIGH_MIN", Some("6.5")),
            ],
            || {
                let env_sev = env_severity_overrides();
                let cli_sev = SeverityOverrides {
                    v3_high: Some(6.0),
                    ..Default::default()
                };
                let cfg = load_with_severity(None, env_sev, cli_sev);
                assert_eq!(cfg.severity.v3.high_min, 6.0);
            },
        );
    }

    #[test]
    fn severity_v2_v4_independently_configurable() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("xdg").join("verilyze");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("verilyze.conf"),
            "[severity.v2]\ncritical_min = 10.0\n[severity.v4]\nhigh_min = 6.5\n",
        )
        .unwrap();
        temp_env::with_var(
            "XDG_CONFIG_HOME",
            Some(dir.path().join("xdg").to_str().unwrap()),
            || {
                let cfg = load_no_severity(None);
                assert_eq!(cfg.severity.v2.critical_min, 10.0);
                assert_eq!(cfg.severity.v4.high_min, 6.5);
                // v3 unchanged
                assert_eq!(cfg.severity.v3.critical_min, 9.0);
            },
        );
    }

    /// Helper: call load() with no env or CLI severity overrides.
    fn load_no_severity(config_file: Option<&str>) -> EffectiveConfig {
        load_with_severity(
            config_file,
            SeverityOverrides::default(),
            SeverityOverrides::default(),
        )
    }

    /// Helper: call load() with given severity overrides.
    fn load_with_severity(
        config_file: Option<&str>,
        env_sev: SeverityOverrides,
        cli_sev: SeverityOverrides,
    ) -> EffectiveConfig {
        load(
            config_file,
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            env_sev,
            cli_sev,
        )
        .unwrap()
    }

    #[test]
    fn reachability_mode_default_is_tier_b() {
        let cfg = load_with_reachability(None, None, None, None);
        assert_eq!(cfg.reachability_mode, ReachabilityMode::TierB);
    }

    #[test]
    fn reachability_mode_from_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("verilyze.conf");
        std::fs::write(&config_path, "reachability_mode = \"off\"\n")
            .expect("write config");
        let cfg = load_with_reachability(
            Some(config_path.to_str().expect("path utf-8")),
            None,
            None,
            None,
        );
        assert_eq!(cfg.reachability_mode, ReachabilityMode::Off);
    }

    #[test]
    fn reachability_mode_env_overrides_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("verilyze.conf");
        std::fs::write(
            &config_path,
            "reachability_mode = \"best-available\"\n",
        )
        .expect("write config");
        temp_env::with_var("VLZ_REACHABILITY_MODE", Some("off"), || {
            let cfg = load_with_reachability(
                Some(config_path.to_str().expect("path utf-8")),
                env_reachability_mode(),
                None,
                None,
            );
            assert_eq!(cfg.reachability_mode, ReachabilityMode::Off);
        });
    }

    #[test]
    fn reachability_mode_cli_overrides_env_and_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("verilyze.conf");
        std::fs::write(&config_path, "reachability_mode = \"off\"\n")
            .expect("write config");
        temp_env::with_var(
            "VLZ_REACHABILITY_MODE",
            Some("best-available"),
            || {
                let cfg = load_with_reachability(
                    Some(config_path.to_str().expect("path utf-8")),
                    env_reachability_mode(),
                    Some(ReachabilityMode::BestAvailable),
                    None,
                );
                assert_eq!(
                    cfg.reachability_mode,
                    ReachabilityMode::BestAvailable
                );
            },
        );
    }

    #[test]
    fn reachability_mode_invalid_env_value_returns_none() {
        temp_env::with_var("VLZ_REACHABILITY_MODE", Some("invalid"), || {
            assert_eq!(env_reachability_mode(), None);
        });
    }

    #[test]
    fn reachability_mode_invalid_file_value_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("verilyze.conf");
        std::fs::write(&config_path, "reachability_mode = \"bad\"\n")
            .expect("write config");
        let result = load_with_reachability_overrides(
            Some(config_path.to_str().expect("path utf-8")),
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            Default::default(),
            Default::default(),
        );
        assert!(matches!(
            result,
            Err(ConfigError::InvalidReachabilityMode { .. })
        ));
    }

    fn load_with_reachability(
        config_file: Option<&str>,
        env_mode: Option<ReachabilityMode>,
        cli_mode: Option<ReachabilityMode>,
        env_sev: Option<SeverityOverrides>,
    ) -> EffectiveConfig {
        load_with_reachability_overrides(
            config_file,
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
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            env_mode,
            cli_mode,
            env_sev.unwrap_or_default(),
            Default::default(),
        )
        .expect("load config")
    }
}
