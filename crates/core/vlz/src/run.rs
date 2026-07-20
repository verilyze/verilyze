// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::benchmark_metrics::BenchmarkMetrics;
use anyhow::{Context, Result, anyhow};
#[cfg(feature = "completions")]
use clap::CommandFactory as _;
use log::{LevelFilter, error, info};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use crate::cache_warm::{
    CacheWarmOptions, OFFLINE_CACHE_MISS_MESSAGE, warm_cache_for_packages,
};
use crate::cli::{Cli, Commands, FpCommands};
use crate::package_resolve::resolve_packages_for_path;

/// Write all bytes to `w`; propagates I/O errors (e.g. BrokenPipe).
/// Used by write_stdout and by tests with a buffer.
pub fn write_all_to<W: Write>(w: &mut W, s: &str) -> std::io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// True if the error chain contains an I/O BrokenPipe.
pub fn is_broken_pipe(e: &anyhow::Error) -> bool {
    for cause in e.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::BrokenPipe
        {
            return true;
        }
    }
    false
}

/// Handle write failure: exit 0 on BrokenPipe, panic otherwise.
fn handle_stdout_write_error(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    panic!("failed printing to stdout: {}", e);
}

/// Write to stdout; exit 0 on broken pipe (e.g. `| less` then `q`).
/// Use for all user-facing stdout so every command handles piped output safely.
pub fn write_stdout(s: &str) {
    let mut out = std::io::stdout().lock();
    if let Err(e) = write_all_to(&mut out, s) {
        handle_stdout_write_error(e);
    }
}

/// True if cache entry key matches pattern (exact substring or prefix when pattern ends with *).
/// Used by `db set-ttl --pattern`.
pub fn entry_key_matches_pattern(key: &str, pattern: &str) -> bool {
    key.contains(pattern)
        || pattern
            .strip_suffix('*')
            .map(|prefix| key.starts_with(prefix))
            .unwrap_or(false)
}

/// Return the CVE lookup result for benchmark mode: always empty, bypassing cache and network.
/// FR-029: benchmark disables cache and network so that only the scan/parse/resolve pipeline
/// is timed without I/O interference.
pub fn benchmark_lookup_result(
    pkg: &vlz_db::Package,
) -> (vlz_db::Package, Vec<vlz_db::CveRecord>) {
    (pkg.clone(), vec![])
}

/// True if CVE meets min_score threshold (FR-014). When cvss_score is None, passes only if min_score <= 0.
pub fn cve_meets_score_threshold(
    cvss_score: Option<f32>,
    min_score: f32,
) -> bool {
    cvss_score
        .map(|s| s >= min_score)
        .unwrap_or(min_score <= 0.0)
}

/// Compute scan exit code from CVE count meeting threshold (FR-014, FR-010).
pub fn compute_scan_exit_code(
    meeting_threshold: usize,
    min_count: usize,
    exit_code_on_cve: Option<u8>,
) -> i32 {
    let trigger = if min_count == 0 {
        meeting_threshold >= 1
    } else {
        meeting_threshold >= min_count
    };
    if trigger {
        exit_code_on_cve.unwrap_or(86) as i32
    } else {
        0
    }
}

/// Map verbosity count (number of `-v` flags) to log level.
pub fn log_level_from_verbosity_count(count: usize) -> LevelFilter {
    match count {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

#[cfg_attr(not(feature = "perf-instrumentation"), allow(dead_code))]
fn tier_b_metrics_line(
    elapsed_ms: u128,
    enum_calls: u64,
    files_enumerated: u64,
    read_attempts: u64,
    read_successes: u64,
) -> Option<String> {
    #[cfg(feature = "perf-instrumentation")]
    {
        Some(format!(
            "Tier-B reachability finished in {} ms (enum_calls={}, files_enumerated={}, read_attempts={}, read_successes={})",
            elapsed_ms,
            enum_calls,
            files_enumerated,
            read_attempts,
            read_successes
        ))
    }
    #[cfg(not(feature = "perf-instrumentation"))]
    {
        let _ = (
            elapsed_ms,
            enum_calls,
            files_enumerated,
            read_attempts,
            read_successes,
        );
        None
    }
}

fn should_apply_tier_b(mode: crate::config::ReachabilityMode) -> bool {
    match mode {
        crate::config::ReachabilityMode::Off => false,
        crate::config::ReachabilityMode::TierB
        | crate::config::ReachabilityMode::BestAvailable => true,
    }
}

fn should_apply_tier_c(mode: crate::config::ReachabilityMode) -> bool {
    matches!(mode, crate::config::ReachabilityMode::BestAvailable)
}

async fn select_provider_impl(
    provider: Option<String>,
    effective: &crate::config::EffectiveConfig,
) -> Result<Arc<Box<dyn vlz_cve_client::CveProvider + Send + Sync + 'static>>>
{
    let mut prov = crate::registry::providers()
        .lock()
        .expect("PROVIDERS lock poisoned");
    if prov.is_empty() {
        error!("No CveProvider plug-in registered");
        return Err(anyhow!("No CveProvider plug-in registered"));
    }
    let inner = if let Some(ref name) = provider {
        let pos = prov.iter().position(|p| p.name() == name.as_str());
        match pos {
            Some(i) => prov.remove(i),
            None => {
                error!(
                    "Unknown provider: {} (use `vlz db list-providers` to list)",
                    name
                );
                return Err(anyhow!(
                    "Unknown provider: {} (use `vlz db list-providers` to list)",
                    name
                ));
            }
        }
    } else {
        prov.remove(0)
    };
    let backoff_config = vlz_cve_client::BackoffConfig {
        base_ms: effective.backoff_base_ms,
        max_ms: effective.backoff_max_ms,
        max_retries: effective.max_retries,
    };
    let wrapped =
        vlz_cve_client::RetryingCveProvider::new(inner, backoff_config);
    Ok(Arc::new(Box::new(wrapped)))
}

/// MOD-009, DOC-013: Show man page via `vlz help` or `vlz help <subcommand>`.
/// When docs feature is disabled, prints error and returns 2.
fn run_help(_subcommand: Option<&str>) -> Result<i32> {
    #[cfg(not(feature = "docs"))]
    {
        eprintln!(
            "Error: vlz was built without documentation. To rebuild with \
             documentation, run `cargo build`, or find the documentation online \
             at {}.",
            crate::cli::DOCS_ONLINE_URL
        );
        return Ok(2);
    }

    #[cfg(feature = "docs")]
    {
        const MAN_VLZ: &str =
            include_str!(concat!(env!("OUT_DIR"), "/embedded_vlz.1"));
        let mut tmp = tempfile::Builder::new()
            .suffix(".1")
            .tempfile()
            .context("Creating temp file for man page")?;
        std::io::Write::write_all(&mut tmp, MAN_VLZ.as_bytes())
            .context("Writing man page to temp file")?;
        tmp.as_file().sync_all().context("Syncing temp file")?;
        let path = tmp.path();
        let status = std::process::Command::new("man")
            .args(["-l", path.to_str().unwrap_or_default()])
            .status();
        match status {
            Ok(s) if s.success() => Ok(0),
            Ok(s) => Ok(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!(
                    "Error: could not run 'man' to display documentation: {}. \
                     Try 'man vlz' if installed via package manager, or see {}.",
                    e,
                    crate::cli::DOCS_ONLINE_URL
                );
                Ok(2)
            }
        }
    }
}

/// Core entry point: runs the requested command and returns the exit code.
/// Caller is responsible for initialising the logger and for calling `process::exit(code)`.
pub async fn run(args: Cli) -> Result<i32> {
    // FR-028: generate-completions needs no config or DB; handle early.
    #[cfg(feature = "completions")]
    if let Commands::GenerateCompletions { shell } = &args.cmd {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        clap_complete::generate(*shell, &mut cmd, "vlz", &mut buf);
        let filtered =
            crate::completion::filter_completion_output(*shell, &buf);
        std::io::stdout()
            .write_all(&filtered)
            .map_err(|e| anyhow::anyhow!("write completions: {e}"))?;
        return Ok(0);
    }

    // MOD-009, DOC-013: help shows man page; handle early (no config or DB).
    if let Commands::Help { subcommand } = &args.cmd {
        return run_help(subcommand.as_deref());
    }

    // Resolve CLI cache TTL, cache DB path, and project_id from subcommand.
    let (
        cli_cache_ttl_secs,
        cli_cache_db,
        cli_ignore_db,
        cli_project_id,
        cli_reachability_mode_raw,
    ) = match &args.cmd {
        Commands::Db { cache_ttl_secs, .. } => {
            (*cache_ttl_secs, None, None, None, None)
        }
        Commands::Scan {
            cache_ttl_secs,
            cache_db,
            ignore_db,
            project_id,
            reachability_mode,
            ..
        } => (
            *cache_ttl_secs,
            cache_db.clone(),
            ignore_db.clone(),
            project_id.clone(),
            reachability_mode.clone(),
        ),
        Commands::Preload {
            cache_ttl_secs,
            cache_db,
            ..
        } => (*cache_ttl_secs, cache_db.clone(), None, None, None),
        Commands::Fp { .. } => (None, None, None, None, None),
        _ => (None, None, None, None, None),
    };

    let cli_reachability_mode = cli_reachability_mode_raw
        .as_deref()
        .map(|mode| {
            crate::config::parse_reachability_mode(mode, "command line")
        })
        .transpose()
        .map_err(|e| {
            error!("{}", e);
            anyhow!(e)
        })?;

    let (
        cli_provider_http_connect_timeout_secs,
        cli_provider_http_request_timeout_secs,
        cli_tls_crl_bundle,
    ) = match &args.cmd {
        Commands::Scan {
            provider_http_connect_timeout_secs,
            provider_http_request_timeout_secs,
            tls_crl_bundle,
            ..
        }
        | Commands::Preload {
            provider_http_connect_timeout_secs,
            provider_http_request_timeout_secs,
            tls_crl_bundle,
            ..
        } => (
            *provider_http_connect_timeout_secs,
            *provider_http_request_timeout_secs,
            tls_crl_bundle.clone(),
        ),
        _ => (None, None, None),
    };

    // Load config from files + env + CLI for DB paths and TTL.
    let early_cfg = crate::config::load_with_reachability_overrides(
        args.config.as_deref(),
        crate::config::env_parallel(),
        crate::config::env_parallel_resolutions(),
        crate::config::env_cache_db(),
        crate::config::env_ignore_db(),
        crate::config::env_cache_ttl_secs(),
        crate::config::env_min_score(),
        crate::config::env_min_count(),
        crate::config::env_exit_code_on_cve(),
        crate::config::env_fp_exit_code(),
        crate::config::env_project_id(),
        crate::config::env_backoff_base_ms(),
        crate::config::env_backoff_max_ms(),
        crate::config::env_max_retries(),
        crate::config::env_provider_http_connect_timeout_secs(),
        crate::config::env_provider_http_request_timeout_secs(),
        crate::config::env_tls_crl_bundle(),
        None,
        None,
        cli_cache_db.as_deref(),
        cli_ignore_db.as_deref(),
        cli_cache_ttl_secs,
        false,
        false,
        None,
        None,
        None,
        None,
        cli_project_id,
        false,
        None,
        None,
        None,
        cli_provider_http_connect_timeout_secs,
        cli_provider_http_request_timeout_secs,
        cli_tls_crl_bundle,
        crate::config::env_reachability_mode(),
        cli_reachability_mode,
        false,
        false,
        false,
        false,
        crate::config::env_severity_overrides(),
        crate::config::SeverityOverrides::default(),
    )
    .map_err(|e| {
        error!("{}", e);
        anyhow!(e)
    })?;

    let cache_path = early_cfg
        .cache_db
        .clone()
        .unwrap_or_else(crate::config::default_cache_path);

    // -----------------------------------------------------------------
    // 3) Initialise plug-ins (they register themselves via the macro)
    // -----------------------------------------------------------------
    #[cfg(feature = "redb")]
    {
        if let Some(parent) = cache_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)
                .context("Creating cache directory")?;
        }
        crate::registry::ensure_default_db_backend_with_path(
            cache_path,
            early_cfg.cache_ttl_secs,
        )
        .map_err(|e| {
            error!("Failed to open cache database: {}", e);
            anyhow!("Failed to open cache database: {}", e)
        })?;
        if args.verbose > 0 {
            info!("Cache TTL: {} s", early_cfg.cache_ttl_secs);
        }
    }
    crate::registry::ensure_default_manifest_finder();
    crate::registry::ensure_default_parser();
    crate::registry::ensure_default_resolver();
    crate::registry::ensure_default_reachability_analyzer();
    crate::registry::ensure_default_cve_provider(&early_cfg);
    crate::registry::ensure_default_reporter();
    crate::registry::ensure_default_integrity_checker();

    let db_backend = {
        let mut backends = crate::registry::db_backends()
            .lock()
            .expect("DB_BACKENDS lock poisoned");
        if backends.is_empty() {
            error!("No DatabaseBackend implementation was registered.");
            return Err(anyhow!(
                "No DatabaseBackend implementation was registered."
            ));
        }
        let backend: Box<dyn vlz_db::DatabaseBackend + Send + Sync + 'static> =
            backends.remove(0);
        Arc::new(backend)
    };

    db_backend
        .init()
        .await
        .context("Failed to initialise DB backend")?;

    // -----------------------------------------------------------------
    // 4) Dispatch sub-command
    // -----------------------------------------------------------------
    match args.cmd {
        Commands::Scan {
            root,
            format,
            output,
            report,
            provider,
            parallel: cli_parallel,
            parallel_resolutions: cli_parallel_resolutions,
            cache_db: cli_cache_db,
            ignore_db: cli_ignore_db,
            cache_ttl_secs: cli_cache_ttl_secs,
            offline,
            benchmark,
            min_score: cli_min_score,
            min_count: cli_min_count,
            exit_code: cli_exit_code,
            fp_exit_code: cli_fp_exit_code,
            project_id: cli_project_id,
            package_manager_required,
            keep_ephemeral_venv,
            allow_dependency_code_execution,
            allow_direct_only_fallback,
            fail_fast,
            backoff_base: cli_backoff_base,
            backoff_max: cli_backoff_max,
            max_retries: cli_max_retries,
            provider_http_connect_timeout_secs: cli_provider_http_connect_scan,
            provider_http_request_timeout_secs: cli_provider_http_request_scan,
            tls_crl_bundle: cli_tls_crl_bundle_scan,
            reachability_mode: _cli_reachability_mode_scan,
            scan_exclude_dir: cli_scan_exclude_dir_scan,
            lock_file: cli_lock_files_scan,
            severity_v2_critical_min,
            severity_v2_high_min,
            severity_v2_medium_min,
            severity_v2_low_min,
            severity_v3_critical_min,
            severity_v3_high_min,
            severity_v3_medium_min,
            severity_v3_low_min,
            severity_v4_critical_min,
            severity_v4_high_min,
            severity_v4_medium_min,
            severity_v4_low_min,
        } => {
            let cli_severity = crate::config::SeverityOverrides {
                v2_critical: severity_v2_critical_min,
                v2_high: severity_v2_high_min,
                v2_medium: severity_v2_medium_min,
                v2_low: severity_v2_low_min,
                v3_critical: severity_v3_critical_min,
                v3_high: severity_v3_high_min,
                v3_medium: severity_v3_medium_min,
                v3_low: severity_v3_low_min,
                v4_critical: severity_v4_critical_min,
                v4_high: severity_v4_high_min,
                v4_medium: severity_v4_medium_min,
                v4_low: severity_v4_low_min,
            };
            let mut effective =
                crate::config::load_with_reachability_overrides(
                    args.config.as_deref(),
                    crate::config::env_parallel(),
                    crate::config::env_parallel_resolutions(),
                    crate::config::env_cache_db(),
                    crate::config::env_ignore_db(),
                    crate::config::env_cache_ttl_secs(),
                    crate::config::env_min_score(),
                    crate::config::env_min_count(),
                    crate::config::env_exit_code_on_cve(),
                    crate::config::env_fp_exit_code(),
                    crate::config::env_project_id(),
                    crate::config::env_backoff_base_ms(),
                    crate::config::env_backoff_max_ms(),
                    crate::config::env_max_retries(),
                    crate::config::env_provider_http_connect_timeout_secs(),
                    crate::config::env_provider_http_request_timeout_secs(),
                    crate::config::env_tls_crl_bundle(),
                    cli_parallel,
                    cli_parallel_resolutions,
                    cli_cache_db.as_deref(),
                    cli_ignore_db.as_deref(),
                    cli_cache_ttl_secs,
                    offline,
                    benchmark,
                    cli_min_score,
                    cli_min_count,
                    cli_exit_code,
                    cli_fp_exit_code,
                    cli_project_id,
                    package_manager_required,
                    cli_backoff_base,
                    cli_backoff_max,
                    cli_max_retries,
                    cli_provider_http_connect_scan,
                    cli_provider_http_request_scan,
                    cli_tls_crl_bundle_scan,
                    crate::config::env_reachability_mode(),
                    cli_reachability_mode,
                    keep_ephemeral_venv,
                    allow_dependency_code_execution,
                    allow_direct_only_fallback,
                    fail_fast,
                    crate::config::env_severity_overrides(),
                    cli_severity,
                )
                .map_err(|e| {
                    error!("{}", e);
                    anyhow!(e)
                })?;
            if !cli_scan_exclude_dir_scan.is_empty() {
                effective.scan_exclude_dirs = cli_scan_exclude_dir_scan;
            }
            #[cfg(feature = "python")]
            if !cli_lock_files_scan.is_empty() {
                effective.python_lock_files =
                    vlz_python::normalize_lock_file_allowlist(
                        &cli_lock_files_scan,
                    )
                    .map_err(|message| {
                        error!("{}", message);
                        anyhow!(message)
                    })?;
            }
            let code = run_scan(
                root,
                format,
                output,
                report,
                provider,
                effective,
                args.verbose,
                db_backend,
            )
            .await?;
            Ok(code)
        }

        Commands::Languages => {
            let finders = crate::registry::finders()
                .lock()
                .expect("FINDERS lock poisoned");
            let mut languages: Vec<String> = finders
                .iter()
                .map(|f| f.language_name().to_string())
                .collect();
            languages.sort();
            languages.dedup();
            for lang in languages {
                write_stdout(&format!("{}\n", lang));
            }
            Ok(0)
        }

        Commands::Config { list, example, set } => {
            if example {
                let cfg = crate::config::load(
                    args.config.as_deref(),
                    crate::config::env_parallel(),
                    crate::config::env_parallel_resolutions(),
                    crate::config::env_cache_db(),
                    crate::config::env_ignore_db(),
                    crate::config::env_cache_ttl_secs(),
                    crate::config::env_min_score(),
                    crate::config::env_min_count(),
                    crate::config::env_exit_code_on_cve(),
                    crate::config::env_fp_exit_code(),
                    crate::config::env_project_id(),
                    crate::config::env_backoff_base_ms(),
                    crate::config::env_backoff_max_ms(),
                    crate::config::env_max_retries(),
                    crate::config::env_provider_http_connect_timeout_secs(),
                    crate::config::env_provider_http_request_timeout_secs(),
                    crate::config::env_tls_crl_bundle(),
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
                    crate::config::env_severity_overrides(),
                    crate::config::SeverityOverrides::default(),
                )
                .unwrap_or_default();
                let content = crate::config_example::generate_example(&cfg);
                write_stdout(&content);
                return Ok(0);
            }
            if let Some(pair) = set {
                let (key, value) = match crate::cli::parse_config_set_arg(
                    pair.as_str(),
                ) {
                    Some((k, v)) => (k, v),
                    None => {
                        error!(
                            "Invalid --set argument; use KEY=VALUE (e.g. python.regex=\"^requirements\\.txt$\")"
                        );
                        return Err(anyhow!(
                            "Invalid --set argument; use KEY=VALUE"
                        ));
                    }
                };
                if let Err(e) = crate::config::set_config_key(key, value) {
                    error!("{}", e);
                    return Err(e.into());
                }
                write_stdout(&format!("Set {} = {}\n", key, value));
            }
            if list {
                let cfg = crate::config::load(
                    args.config.as_deref(),
                    crate::config::env_parallel(),
                    crate::config::env_parallel_resolutions(),
                    crate::config::env_cache_db(),
                    crate::config::env_ignore_db(),
                    crate::config::env_cache_ttl_secs(),
                    crate::config::env_min_score(),
                    crate::config::env_min_count(),
                    crate::config::env_exit_code_on_cve(),
                    crate::config::env_fp_exit_code(),
                    crate::config::env_project_id(),
                    crate::config::env_backoff_base_ms(),
                    crate::config::env_backoff_max_ms(),
                    crate::config::env_max_retries(),
                    crate::config::env_provider_http_connect_timeout_secs(),
                    crate::config::env_provider_http_request_timeout_secs(),
                    crate::config::env_tls_crl_bundle(),
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
                    crate::config::env_severity_overrides(),
                    crate::config::SeverityOverrides::default(),
                )
                .unwrap_or_default();
                // DOC-003: config --list shows effective values (what vlz actually uses).
                let cache_db = cfg
                    .cache_db
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| {
                        crate::config::default_cache_path()
                            .display()
                            .to_string()
                    });
                let ignore_db = cfg
                    .ignore_db
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| {
                        crate::config::default_ignore_path()
                            .display()
                            .to_string()
                    });
                write_stdout(&format!("cache_db = {}\n", cache_db));
                write_stdout(&format!("ignore_db = {}\n", ignore_db));
                write_stdout(&format!(
                    "parallel_queries = {}\n",
                    cfg.parallel_queries
                ));
                write_stdout(&format!(
                    "parallel_resolutions = {}\n",
                    cfg.parallel_resolutions
                ));
                write_stdout(&format!(
                    "scan_exclude_dirs = {}\n",
                    cfg.scan_exclude_dirs.join(",")
                ));
                let reachability_mode = match cfg.reachability_mode {
                    crate::config::ReachabilityMode::Off => "off",
                    crate::config::ReachabilityMode::TierB => "tier-b",
                    crate::config::ReachabilityMode::BestAvailable => {
                        "best-available"
                    }
                };
                write_stdout(&format!(
                    "reachability_mode = {}\n",
                    reachability_mode
                ));
                write_stdout(&format!(
                    "cache_ttl_secs = {}\n",
                    cfg.cache_ttl_secs
                ));
                write_stdout(&format!("min_score = {}\n", cfg.min_score));
                write_stdout(&format!("min_count = {}\n", cfg.min_count));
                write_stdout(&format!(
                    "exit_code_on_cve = {}\n",
                    cfg.exit_code_on_cve.unwrap_or(86)
                ));
                write_stdout(&format!(
                    "fp_exit_code = {}\n",
                    cfg.fp_exit_code.unwrap_or(0)
                ));
                let project_id = cfg.project_id.as_deref().unwrap_or("");
                write_stdout(&format!("project_id = {}\n", project_id));
                write_stdout(&format!(
                    "backoff_base_ms = {}\n",
                    cfg.backoff_base_ms
                ));
                write_stdout(&format!(
                    "backoff_max_ms = {}\n",
                    cfg.backoff_max_ms
                ));
                write_stdout(&format!("max_retries = {}\n", cfg.max_retries));
                write_stdout(&format!(
                    "provider_http_connect_timeout_secs = {}\n",
                    cfg.provider_http_connect_timeout_secs
                ));
                write_stdout(&format!(
                    "provider_http_request_timeout_secs = {}\n",
                    cfg.provider_http_request_timeout_secs
                ));
                let tls_crl = cfg
                    .tls_crl_bundle
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                write_stdout(&format!("tls_crl_bundle = {}\n", tls_crl));
                write_stdout(&format!(
                    "keep_ephemeral_venv = {}\n",
                    cfg.keep_ephemeral_venv
                ));
                write_stdout(&format!(
                    "allow_dependency_code_execution = {}\n",
                    cfg.allow_dependency_code_execution
                ));
                write_stdout(&format!(
                    "allow_direct_only_fallback = {}\n",
                    cfg.allow_direct_only_fallback
                ));
                write_stdout(&format!("fail_fast = {}\n", cfg.fail_fast));
                write_stdout(&format!(
                    "severity_v2_critical_min = {}\n",
                    cfg.severity.v2.critical_min
                ));
                write_stdout(&format!(
                    "severity_v2_high_min = {}\n",
                    cfg.severity.v2.high_min
                ));
                write_stdout(&format!(
                    "severity_v2_medium_min = {}\n",
                    cfg.severity.v2.medium_min
                ));
                write_stdout(&format!(
                    "severity_v2_low_min = {}\n",
                    cfg.severity.v2.low_min
                ));
                write_stdout(&format!(
                    "severity_v3_critical_min = {}\n",
                    cfg.severity.v3.critical_min
                ));
                write_stdout(&format!(
                    "severity_v3_high_min = {}\n",
                    cfg.severity.v3.high_min
                ));
                write_stdout(&format!(
                    "severity_v3_medium_min = {}\n",
                    cfg.severity.v3.medium_min
                ));
                write_stdout(&format!(
                    "severity_v3_low_min = {}\n",
                    cfg.severity.v3.low_min
                ));
                write_stdout(&format!(
                    "severity_v4_critical_min = {}\n",
                    cfg.severity.v4.critical_min
                ));
                write_stdout(&format!(
                    "severity_v4_high_min = {}\n",
                    cfg.severity.v4.high_min
                ));
                write_stdout(&format!(
                    "severity_v4_medium_min = {}\n",
                    cfg.severity.v4.medium_min
                ));
                write_stdout(&format!(
                    "severity_v4_low_min = {}\n",
                    cfg.severity.v4.low_min
                ));
                for (lang, re) in &cfg.language_regexes {
                    write_stdout(&format!("{}.regex = {}\n", lang, re));
                }
                if !cfg.python_lock_files.is_empty() {
                    write_stdout(&format!(
                        "python.lock_files = {}\n",
                        cfg.python_lock_files.join(",")
                    ));
                }
            }
            Ok(0)
        }

        Commands::Db { sub, .. } => match sub {
            crate::cli::DbCommands::ListProviders => {
                let providers = crate::registry::providers()
                    .lock()
                    .expect("PROVIDERS lock poisoned");
                for p in providers.iter() {
                    write_stdout(&format!("{}\n", p.name()));
                }
                Ok(0)
            }
            crate::cli::DbCommands::Stats => {
                let stats = db_backend.stats().await?;
                write_stdout(&format!(
                    "Cache entries: {}, hits: {}, misses: {}\n",
                    stats.cached_entries, stats.hits, stats.misses
                ));
                Ok(0)
            }
            crate::cli::DbCommands::Verify => {
                let checker = {
                    let mut c = crate::registry::integrity_checkers()
                        .lock()
                        .expect("INTEGRITY_CHECKERS lock poisoned");
                    if c.is_empty() {
                        None
                    } else {
                        Some(c.remove(0))
                    }
                };
                if let Some(c) = checker {
                    if let Err(e) =
                        c.verify(db_backend.as_ref().as_ref()).await
                    {
                        error!("{}", e);
                        return Ok(1); // FR-033: exit 1 on verify failure
                    }
                    crate::registry::integrity_checkers()
                        .lock()
                        .expect("INTEGRITY_CHECKERS lock poisoned")
                        .insert(0, c);
                } else if let Err(e) = db_backend.verify_integrity().await {
                    error!("{}", e);
                    return Ok(1); // FR-033: exit 1 on verify failure
                }
                write_stdout("Database integrity verified (SHA-256)\n"); // FR-033
                Ok(0)
            }
            crate::cli::DbCommands::Migrate => {
                write_stdout("Database migration completed (nothing to do)\n");
                Ok(0)
            }
            crate::cli::DbCommands::Show { format, full } => {
                let entries = db_backend.list_entries(full).await?;
                if format.as_deref() == Some("json") {
                    write_stdout(
                        &serde_json::to_string_pretty(&entries).unwrap(),
                    );
                    write_stdout("\n");
                } else {
                    for e in &entries {
                        write_stdout(&format!(
                            "{}  ttl={}s  added_at={}  cve_count={}  \
                             cve_ids={:?}\n",
                            e.key,
                            e.ttl_secs,
                            e.added_at_secs,
                            e.cve_count,
                            e.cve_ids
                        ));
                        if let Some(ref raw) = e.raw_vulns {
                            write_stdout(
                                &serde_json::to_string_pretty(raw).unwrap(),
                            );
                            write_stdout("\n");
                        }
                    }
                    if entries.is_empty() {
                        write_stdout("(no cache entries)\n");
                    }
                }
                Ok(0)
            }
            crate::cli::DbCommands::SetTtl {
                secs,
                entry,
                all,
                pattern,
                entries: entries_arg,
            } => {
                use vlz_db::TtlSelector;
                let selector = if let Some(k) = entry {
                    TtlSelector::One(k)
                } else if all {
                    TtlSelector::All
                } else if let Some(p) = pattern {
                    TtlSelector::Multiple(
                        db_backend
                            .list_entries(false)
                            .await?
                            .into_iter()
                            .filter(|e| entry_key_matches_pattern(&e.key, &p))
                            .map(|e| e.key)
                            .collect(),
                    )
                } else if let Some(keys) = entries_arg {
                    TtlSelector::Multiple(
                        keys.split(',')
                            .map(|s| s.trim().to_string())
                            .collect(),
                    )
                } else {
                    error!(
                        "set-ttl requires one of: --entry KEY, --all, --pattern PATTERN, --entries KEY1,KEY2"
                    );
                    return Err(anyhow!(
                        "set-ttl requires one of: --entry, --all, --pattern, --entries"
                    ));
                };
                db_backend.set_ttl(selector, secs).await.map_err(|e| {
                    error!("set_ttl failed: {}", e);
                    anyhow!(e)
                })?;
                write_stdout("TTL updated.\n");
                Ok(0)
            }
        },

        Commands::Fp { sub } => {
            let ignore_path = early_cfg
                .ignore_db
                .clone()
                .unwrap_or_else(crate::config::default_ignore_path);
            #[cfg(feature = "redb")]
            {
                let fp_db = vlz_db_redb::RedbIgnoreDb::with_path(ignore_path)
                    .map_err(|e| {
                        error!("Failed to open ignore database: {}", e);
                        anyhow!("Failed to open ignore database: {}", e)
                    })?;
                match sub {
                    FpCommands::Mark {
                        cve_id,
                        comment,
                        project_id,
                    } => {
                        fp_db
                            .mark(&cve_id, &comment, project_id.as_deref())
                            .map_err(|e| {
                            error!("Failed to mark false positive: {}", e);
                            anyhow!(e)
                        })?;
                        write_stdout(&format!(
                            "Marked {} as false positive\n",
                            cve_id
                        ));
                    }
                    FpCommands::Unmark { cve_id } => {
                        fp_db.unmark(&cve_id).map_err(|e| {
                            error!("Failed to unmark: {}", e);
                            anyhow!(e)
                        })?;
                        write_stdout(&format!("Unmarked {}\n", cve_id));
                    }
                }
                Ok(0)
            }
            #[cfg(not(feature = "redb"))]
            {
                error!("vlz fp requires the redb feature");
                return Err(anyhow!("vlz fp requires the redb feature"));
            }
        }

        Commands::Preload {
            root,
            provider,
            parallel: cli_parallel,
            parallel_resolutions: cli_parallel_resolutions,
            cache_db: cli_cache_db_preload,
            scan_exclude_dir: cli_scan_exclude_dir_preload,
            lock_file: cli_lock_files_preload,
            cache_ttl_secs: cli_cache_ttl_secs_preload,
            offline,
            package_manager_required,
            keep_ephemeral_venv,
            allow_dependency_code_execution,
            allow_direct_only_fallback,
            fail_fast,
            backoff_base: cli_backoff_base,
            backoff_max: cli_backoff_max,
            max_retries: cli_max_retries,
            provider_http_connect_timeout_secs:
                cli_provider_http_connect_preload,
            provider_http_request_timeout_secs:
                cli_provider_http_request_preload,
            tls_crl_bundle: cli_tls_crl_bundle_preload,
        } => {
            let mut effective =
                crate::config::load_with_reachability_overrides(
                    args.config.as_deref(),
                    crate::config::env_parallel(),
                    crate::config::env_parallel_resolutions(),
                    crate::config::env_cache_db(),
                    None,
                    crate::config::env_cache_ttl_secs(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    crate::config::env_backoff_base_ms(),
                    crate::config::env_backoff_max_ms(),
                    crate::config::env_max_retries(),
                    crate::config::env_provider_http_connect_timeout_secs(),
                    crate::config::env_provider_http_request_timeout_secs(),
                    crate::config::env_tls_crl_bundle(),
                    cli_parallel,
                    cli_parallel_resolutions,
                    cli_cache_db_preload.as_deref(),
                    None,
                    cli_cache_ttl_secs_preload,
                    offline,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    package_manager_required,
                    cli_backoff_base,
                    cli_backoff_max,
                    cli_max_retries,
                    cli_provider_http_connect_preload,
                    cli_provider_http_request_preload,
                    cli_tls_crl_bundle_preload,
                    None,
                    None,
                    keep_ephemeral_venv,
                    allow_dependency_code_execution,
                    allow_direct_only_fallback,
                    fail_fast,
                    crate::config::env_severity_overrides(),
                    crate::config::SeverityOverrides::default(),
                )
                .map_err(|e| {
                    error!("{}", e);
                    anyhow!(e)
                })?;
            if !cli_scan_exclude_dir_preload.is_empty() {
                effective.scan_exclude_dirs = cli_scan_exclude_dir_preload;
            }
            #[cfg(feature = "python")]
            if !cli_lock_files_preload.is_empty() {
                effective.python_lock_files =
                    vlz_python::normalize_lock_file_allowlist(
                        &cli_lock_files_preload,
                    )
                    .map_err(|message| {
                        error!("{}", message);
                        anyhow!(message)
                    })?;
            }
            run_preload(root, provider, effective, args.verbose, db_backend)
                .await
        }

        Commands::Help { .. } => {
            // Handled at start of run(); unreachable here
            unreachable!("help returns early")
        }

        #[cfg(feature = "completions")]
        Commands::GenerateCompletions { .. } => {
            // Handled at start of run(); unreachable here
            unreachable!("generate-completions returns early")
        }
    }
}

/// FR-021: resolve manifests and warm the CVE cache without reporting.
async fn run_preload(
    root: Option<String>,
    provider: Option<String>,
    effective: crate::config::EffectiveConfig,
    verbosity: u8,
    db_backend: Arc<Box<dyn vlz_db::DatabaseBackend + Send + Sync + 'static>>,
) -> Result<i32> {
    let resolved =
        resolve_packages_for_path(root, &effective, verbosity).await?;
    if resolved.package_manager_missing {
        return Ok(3);
    }

    let blocking = crate::scan::count_blocking_manifest_failures(
        &resolved.manifest_coverage,
    );
    if blocking > 0
        && let Some(summary) = crate::scan::format_manifest_failure_summary(
            &resolved.manifest_coverage,
            Some(&resolved.root_path),
        )
    {
        eprintln!("{}", summary);
    }
    if resolved.skip_cve_phase {
        return Ok(2);
    }

    let provider_impl = select_provider_impl(provider, &effective).await?;
    let parallel = if effective.parallel_queries == 0 {
        crate::config::DEFAULT_PARALLEL_QUERIES
    } else {
        effective.parallel_queries
    };
    let warm = warm_cache_for_packages(
        &resolved.packages_to_check,
        db_backend,
        provider_impl,
        &CacheWarmOptions {
            parallel,
            offline: effective.offline,
            benchmark: false,
        },
    )
    .await?;

    write_stdout(&format!(
        "Preloaded {} package(s): {} cache hit(s), {} fetched, {} with CVE data.\n",
        warm.summary.packages_checked,
        warm.summary.cache_hits,
        warm.summary.fetched,
        warm.findings.iter().filter(|(_, r)| !r.is_empty()).count(),
    ));

    if warm.summary.offline_cache_miss {
        eprintln!("{}", OFFLINE_CACHE_MISS_MESSAGE);
    }
    if warm.summary.provider_fetch_failed {
        eprintln!(
            "Unable to fetch CVE data from provider. Run with -v for details."
        );
    }

    Ok(crate::scan::pick_exit_code(
        blocking,
        warm.summary.offline_cache_miss,
        warm.summary.provider_fetch_failed,
        0,
    ))
}

/// Runs the scan pipeline; returns the exit code to use (0, 1, 3, 4, 86, etc.).
#[allow(clippy::too_many_arguments)]
async fn run_scan(
    root: Option<String>,
    format: String,
    output: Option<String>,
    report: Vec<String>,
    provider: Option<String>,
    effective: crate::config::EffectiveConfig,
    _verbosity: u8,
    db_backend: Arc<Box<dyn vlz_db::DatabaseBackend + Send + Sync + 'static>>,
) -> Result<i32> {
    let benchmark_start = effective.benchmark.then(Instant::now);

    let resolved =
        resolve_packages_for_path(root, &effective, _verbosity).await?;
    if resolved.package_manager_missing {
        return Ok(3);
    }
    let root_path = resolved.root_path;
    let exclude_dirs = resolved.exclude_dirs;
    let packages_with_manifests = resolved.packages_with_manifests;
    let pkg_declarations = resolved.pkg_declarations;
    let pkg_contexts = resolved.pkg_contexts;
    let packages_to_check = resolved.packages_to_check;
    let manifest_coverage = resolved.manifest_coverage;
    let skip_cve_phase = resolved.skip_cve_phase;

    let provider_impl = select_provider_impl(provider, &effective).await?;

    let reporter: Box<dyn vlz_report::Reporter> =
        if format.eq_ignore_ascii_case("json") {
            Box::new(vlz_report::JsonReporter::new())
        } else if format.eq_ignore_ascii_case("sarif") {
            Box::new(vlz_report::SarifReporter::new())
        } else if format.eq_ignore_ascii_case("cyclonedx") {
            Box::new(vlz_report::CycloneDxReporter::new())
        } else if format.eq_ignore_ascii_case("spdx") {
            Box::new(vlz_report::SpdxReporter::new())
        } else {
            let mut r = crate::registry::reporters()
                .lock()
                .expect("REPORTERS lock poisoned");
            if r.is_empty() {
                error!("No Reporter plug-in registered");
                return Err(anyhow!("No Reporter plug-in registered"));
            }
            r.remove(0)
        };

    // -----------------------------------------------------------------
    // c) Adjust mode flags (offline / benchmark)
    // -----------------------------------------------------------------
    let effective_parallel = if effective.benchmark {
        1
    } else {
        effective.parallel_queries
    };

    let mut pkg_to_manifests: std::collections::HashMap<
        vlz_db::Package,
        std::collections::HashSet<std::path::PathBuf>,
    > = std::collections::HashMap::new();
    for (pkg, path, _) in &packages_with_manifests {
        pkg_to_manifests
            .entry(pkg.clone())
            .or_default()
            .insert(path.clone());
    }

    let mut offline_cache_miss = false;
    let mut provider_fetch_failed = false;
    let mut findings = Vec::new();
    let mut raw_vulns_by_package = std::collections::HashMap::new();

    if !skip_cve_phase {
        let warm = warm_cache_for_packages(
            &packages_to_check,
            db_backend.clone(),
            provider_impl.clone(),
            &CacheWarmOptions {
                parallel: effective_parallel,
                offline: effective.offline,
                benchmark: effective.benchmark,
            },
        )
        .await?;
        offline_cache_miss = warm.summary.offline_cache_miss;
        provider_fetch_failed = warm.summary.provider_fetch_failed;
        findings = warm.findings;
        raw_vulns_by_package = warm.raw_vulns_by_package;
        if provider_fetch_failed && _verbosity > 0 {
            error!(
                "One or more CVE provider fetches failed during cache warm"
            );
        }
    }

    // -----------------------------------------------------------------
    // g2) Apply false-positive filter (FR-015, FR-016)
    // -----------------------------------------------------------------
    let marked_fp: std::collections::HashSet<String> = {
        #[cfg(feature = "redb")]
        {
            let ignore_path = effective
                .ignore_db
                .clone()
                .unwrap_or_else(crate::config::default_ignore_path);
            vlz_db_redb::RedbIgnoreDb::with_path(ignore_path)
                .ok()
                .and_then(|db| {
                    let ignore_db: &dyn vlz_db::IgnoreDb = &db;
                    ignore_db.marked_ids(effective.project_id.as_deref()).ok()
                })
                .unwrap_or_default()
        }
        #[cfg(not(feature = "redb"))]
        std::collections::HashSet::new()
    };
    let had_any_cves_before_fp_filter =
        findings.iter().map(|(_, r)| r.len()).sum::<usize>() > 0;
    let mut findings: Vec<(vlz_db::Package, Vec<vlz_db::CveRecord>)> =
        findings
            .into_iter()
            .map(|(pkg, recs)| {
                let kept: Vec<_> = recs
                    .into_iter()
                    .filter(|cve| !marked_fp.contains(&cve.id))
                    .collect();
                (pkg, kept)
            })
            .filter(|(_, recs)| !recs.is_empty())
            .collect();

    if should_apply_tier_b(effective.reachability_mode) {
        // FR-032 Tier B: import-based reachability hints (conservative unknown when ambiguous).
        #[cfg(feature = "perf-instrumentation")]
        vlz_reachability::reset_tier_b_counters();
        #[cfg(feature = "perf-instrumentation")]
        let tier_b_started_at = Instant::now();
        {
            let reachability_analyzers =
                crate::registry::reachability_analyzers()
                    .lock()
                    .expect("REACHABILITY_ANALYZERS lock poisoned");
            vlz_reachability::apply_tier_b_to_findings(
                &root_path,
                &exclude_dirs,
                &mut findings,
                &pkg_contexts,
                &reachability_analyzers,
            );
        }
        #[cfg(feature = "perf-instrumentation")]
        {
            let (enum_calls, files_enumerated, read_attempts, read_successes) =
                vlz_reachability::snapshot_tier_b_counters();
            if let Some(line) = tier_b_metrics_line(
                tier_b_started_at.elapsed().as_millis(),
                enum_calls,
                files_enumerated,
                read_attempts,
                read_successes,
            ) {
                info!("{}", line);
            }
        }
    }

    if should_apply_tier_c(effective.reachability_mode) {
        let reachability_analyzers = crate::registry::reachability_analyzers()
            .lock()
            .expect("REACHABILITY_ANALYZERS lock poisoned");
        vlz_reachability::apply_tier_c_to_findings(
            &root_path,
            &exclude_dirs,
            &mut findings,
            &pkg_contexts,
            &reachability_analyzers,
            &raw_vulns_by_package,
        );
    }

    #[cfg(feature = "python-tier-d")]
    if should_apply_tier_c(effective.reachability_mode) {
        let reachability_analyzers = crate::registry::reachability_analyzers()
            .lock()
            .expect("REACHABILITY_ANALYZERS lock poisoned");
        vlz_reachability::apply_tier_d_to_findings(
            &root_path,
            &exclude_dirs,
            &mut findings,
            &pkg_contexts,
            &reachability_analyzers,
            &raw_vulns_by_package,
        );
    }

    let real_cve_count: usize = findings.iter().map(|(_, r)| r.len()).sum();
    if had_any_cves_before_fp_filter && real_cve_count == 0 {
        let _ = db_backend.stats().await;
        return Ok(effective.fp_exit_code.unwrap_or(0).into());
    }

    // -----------------------------------------------------------------
    // h) Apply threshold logic (FR-014, FR-010) and decide exit code
    // -----------------------------------------------------------------
    let meeting_threshold: usize = findings
        .iter()
        .flat_map(|(_, recs)| recs.iter())
        .filter(|cve| {
            cve_meets_score_threshold(cve.cvss_score, effective.min_score)
        })
        .count();
    let exit_code = compute_scan_exit_code(
        meeting_threshold,
        effective.min_count,
        effective.exit_code_on_cve,
    );
    let total_cves: usize = findings.iter().map(|(_, r)| r.len()).sum();
    info!(
        "Total CVEs discovered: {}, meeting threshold (score>={}): {}",
        total_cves, effective.min_score, meeting_threshold
    );

    // -----------------------------------------------------------------
    // i) Resolve severity (FR-013) and render the report (FR-007, FR-008, FR-009)
    // -----------------------------------------------------------------
    // FR-013: use configurable severity thresholds from effective config.
    let severity_config = effective.severity.clone();
    let report_findings: Vec<vlz_report::Finding> = findings
        .into_iter()
        .map(|(pkg, recs)| {
            let with_severity: Vec<_> = recs
                .into_iter()
                .map(|cve| {
                    let severity = vlz_report::resolve_severity(
                        cve.cvss_score,
                        cve.cvss_version,
                        &severity_config,
                    );
                    (cve, severity)
                })
                .collect();
            let mut manifest_paths: Vec<std::path::PathBuf> = pkg_to_manifests
                .get(&pkg)
                .map(|s| {
                    s.iter()
                        .map(|p| {
                            p.strip_prefix(&root_path)
                                .map(|r| r.to_path_buf())
                                .unwrap_or_else(|_| p.clone())
                        })
                        .collect()
                })
                .unwrap_or_default();
            manifest_paths.sort();
            let mut declarations =
                pkg_declarations.get(&pkg).cloned().unwrap_or_default();
            for decl in &mut declarations {
                let path = std::path::Path::new(&decl.path);
                decl.path = path
                    .strip_prefix(&root_path)
                    .map(|r| r.display().to_string())
                    .unwrap_or_else(|_| decl.path.clone());
            }
            vlz_db::dedupe_sort_declarations(&mut declarations);
            vlz_report::Finding {
                package: pkg,
                manifest_paths,
                declarations,
                cves: with_severity,
            }
        })
        .collect();
    let report_data = vlz_report::ReportData {
        findings: report_findings,
        all_packages: Some(packages_to_check),
        project_id: effective.project_id.clone(),
        root_path: Some(root_path.clone()),
        manifest_coverage,
        offline_cache_miss,
        provider_fetch_failed,
    };
    if let Some(path) = output.as_deref() {
        reporter
            .render_to_path(&report_data, std::path::Path::new(path))
            .await
            .context("Failed while writing the primary report")?;
    } else {
        reporter
            .render(&report_data)
            .await
            .context("Failed while rendering the report")?;
    }

    if let Some(summary) = crate::scan::format_manifest_failure_summary(
        &report_data.manifest_coverage,
        Some(root_path.as_path()),
    ) {
        eprintln!("{summary}");
    }
    if offline_cache_miss {
        eprintln!(
            "CVE not found in cache, and unable to lookup CVE due to `--offline` argument."
        );
    }
    if provider_fetch_failed {
        eprintln!(
            "Unable to fetch CVE data from provider. Run with -v for details."
        );
    }

    let manifest_blocking = crate::scan::count_blocking_manifest_failures(
        &report_data.manifest_coverage,
    );
    let exit_code = crate::scan::pick_exit_code(
        manifest_blocking,
        offline_cache_miss,
        provider_fetch_failed,
        exit_code,
    );

    // -----------------------------------------------------------------
    // j) Emit optional secondary files (FR-008 --report / --summary-file)
    // -----------------------------------------------------------------
    for spec in report {
        let parts: Vec<_> = spec.splitn(2, ':').collect();
        if parts.len() != 2 {
            error!(
                "Malformed --report argument (alias --summary-file): {}",
                spec
            );
            continue;
        }
        let (fmt, path) = (parts[0].trim().to_lowercase(), parts[1].trim());
        let path = std::path::Path::new(path);
        let reporter: Box<dyn vlz_report::Reporter> = match fmt.as_str() {
            "html" => Box::new(vlz_report::HtmlReporter::new()),
            "json" => Box::new(vlz_report::JsonReporter::new()),
            "sarif" => Box::new(vlz_report::SarifReporter::new()),
            "cyclonedx" => Box::new(vlz_report::CycloneDxReporter::new()),
            "spdx" => Box::new(vlz_report::SpdxReporter::new()),
            "plain" | "text" => Box::new(vlz_report::DefaultReporter::new()),
            _ => {
                error!(
                    "Unknown summary format '{}'; use html, json, sarif, cyclonedx, spdx, or plain",
                    fmt
                );
                continue;
            }
        };
        if let Err(e) = reporter.render_to_path(&report_data, path).await {
            error!(
                "Failed to write {} report to {}: {}",
                fmt,
                path.display(),
                e
            );
        } else {
            info!("Wrote {} report to {}", fmt, path.display());
        }
    }

    // -----------------------------------------------------------------
    // k) Benchmark mode handling (FR-029)
    // -----------------------------------------------------------------
    if effective.benchmark {
        let start =
            benchmark_start.expect("benchmark_start set when benchmark");
        let metrics = BenchmarkMetrics::from_start(start);
        write_stdout(&format!("{}\n", metrics.to_json_line()));
    }

    // -----------------------------------------------------------------
    // l) Persist cache stats then return exit code
    // -----------------------------------------------------------------
    let _ = db_backend.stats().await;
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn write_all_to_writes_bytes() {
        let mut buf = Vec::new();
        let r = write_all_to(&mut buf, "hello\n");
        assert!(r.is_ok());
        assert_eq!(buf, b"hello\n");
    }

    #[test]
    fn write_all_to_empty_string() {
        let mut buf = Vec::new();
        let r = write_all_to(&mut buf, "");
        assert!(r.is_ok());
        assert!(buf.is_empty());
    }

    #[test]
    fn write_all_to_broken_pipe_propagates_error() {
        struct BrokenPipeWriter;
        impl Write for BrokenPipeWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut w = BrokenPipeWriter;
        let r = write_all_to(&mut w, "x");
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn write_all_to_flush_error_propagates() {
        struct FlushFailsWriter;
        impl Write for FlushFailsWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "flush failed",
                ))
            }
        }
        let mut w = FlushFailsWriter;
        let r = write_all_to(&mut w, "x");
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn log_level_from_verbosity_count_zero_is_info() {
        assert_eq!(log_level_from_verbosity_count(0), log::LevelFilter::Info);
    }

    #[test]
    fn log_level_from_verbosity_count_one_is_debug() {
        assert_eq!(log_level_from_verbosity_count(1), log::LevelFilter::Debug);
    }

    #[test]
    fn log_level_from_verbosity_count_two_or_more_is_trace() {
        assert_eq!(log_level_from_verbosity_count(2), log::LevelFilter::Trace);
        assert_eq!(
            log_level_from_verbosity_count(100),
            log::LevelFilter::Trace
        );
    }

    #[test]
    fn is_broken_pipe_detects_io_error() {
        let e: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe")
                .into();
        assert!(is_broken_pipe(&e));
    }

    #[test]
    fn is_broken_pipe_ignores_other_errors() {
        let e: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found")
                .into();
        assert!(!is_broken_pipe(&e));
    }

    #[test]
    fn is_broken_pipe_ignores_non_io_error() {
        let e: anyhow::Error = anyhow::anyhow!("some other error");
        assert!(!is_broken_pipe(&e));
    }

    #[test]
    #[should_panic(expected = "failed printing to stdout")]
    fn handle_stdout_write_error_panics_on_non_broken_pipe() {
        handle_stdout_write_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
    }

    #[test]
    fn cve_meets_score_threshold_with_score() {
        assert!(cve_meets_score_threshold(Some(7.0), 5.0));
        assert!(cve_meets_score_threshold(Some(5.0), 5.0));
        assert!(!cve_meets_score_threshold(Some(3.0), 5.0));
    }

    #[test]
    fn cve_meets_score_threshold_none() {
        assert!(cve_meets_score_threshold(None, 0.0));
        assert!(cve_meets_score_threshold(None, -1.0));
        assert!(!cve_meets_score_threshold(None, 1.0));
    }

    #[test]
    fn entry_key_matches_pattern_substring() {
        assert!(entry_key_matches_pattern("foo::1.0", "foo"));
        assert!(entry_key_matches_pattern("pkg::2.0", "2"));
        assert!(!entry_key_matches_pattern("foo::1.0", "bar"));
    }

    #[test]
    fn entry_key_matches_pattern_wildcard() {
        assert!(entry_key_matches_pattern("foo::1.0", "foo*"));
        assert!(entry_key_matches_pattern("foobar", "foo*"));
        assert!(!entry_key_matches_pattern("xfoo", "foo*"));
        assert!(entry_key_matches_pattern("pkg", "pkg*"));
    }

    #[test]
    fn compute_scan_exit_code_no_trigger() {
        assert_eq!(compute_scan_exit_code(0, 1, Some(99)), 0);
        assert_eq!(compute_scan_exit_code(0, 0, Some(86)), 0);
    }

    #[test]
    fn compute_scan_exit_code_trigger_default() {
        assert_eq!(compute_scan_exit_code(1, 0, None), 86);
        assert_eq!(compute_scan_exit_code(5, 3, None), 86);
    }

    #[test]
    fn compute_scan_exit_code_trigger_custom() {
        assert_eq!(compute_scan_exit_code(1, 0, Some(99)), 99);
        assert_eq!(compute_scan_exit_code(2, 2, Some(1)), 1);
    }

    #[test]
    fn benchmark_lookup_result_returns_empty_cves() {
        // FR-029: benchmark mode skips cache and network; result is always empty.
        let pkg = vlz_db::Package {
            name: "mylib".to_string(),
            version: "1.2.3".to_string(),
            ecosystem: None,
        };
        let (out_pkg, cves) = benchmark_lookup_result(&pkg);
        assert_eq!(out_pkg.name, pkg.name);
        assert_eq!(out_pkg.version, pkg.version);
        assert!(cves.is_empty());
    }

    #[cfg(feature = "perf-instrumentation")]
    #[test]
    fn tier_b_metrics_line_present_when_feature_enabled() {
        let line = tier_b_metrics_line(12, 3, 4, 5, 6).expect("metrics line");
        assert!(line.contains("12 ms"));
        assert!(line.contains("enum_calls=3"));
        assert!(line.contains("files_enumerated=4"));
        assert!(line.contains("read_attempts=5"));
        assert!(line.contains("read_successes=6"));
    }

    #[cfg(not(feature = "perf-instrumentation"))]
    #[test]
    fn tier_b_metrics_line_absent_when_feature_disabled() {
        assert!(tier_b_metrics_line(12, 3, 4, 5, 6).is_none());
    }

    #[test]
    fn should_apply_tier_b_depends_on_mode() {
        assert!(!should_apply_tier_b(crate::config::ReachabilityMode::Off));
        assert!(should_apply_tier_b(crate::config::ReachabilityMode::TierB));
        assert!(should_apply_tier_b(
            crate::config::ReachabilityMode::BestAvailable
        ));
    }

    #[test]
    fn should_apply_tier_c_only_for_best_available() {
        assert!(!should_apply_tier_c(crate::config::ReachabilityMode::Off));
        assert!(!should_apply_tier_c(crate::config::ReachabilityMode::TierB));
        assert!(should_apply_tier_c(
            crate::config::ReachabilityMode::BestAvailable
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn select_provider_impl_empty_registry_errors() {
        let _guard = crate::registry::registry_test_mutex()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::registry::clear_providers();
        let effective = crate::config::EffectiveConfig::default();
        let err = match select_provider_impl(None, &effective).await {
            Ok(_) => panic!("empty providers must error"),
            Err(e) => e,
        };
        assert!(
            err.to_string()
                .contains("No CveProvider plug-in registered"),
            "got: {err}"
        );
    }
}
