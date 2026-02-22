// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use log::{error, info, LevelFilter};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::cli::{Cli, Commands, FpCommands};

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
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::BrokenPipe {
                return true;
            }
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

/// True if CVE meets min_score threshold (FR-014). When cvss_score is None, passes only if min_score <= 0.
pub fn cve_meets_score_threshold(cvss_score: Option<f32>, min_score: f32) -> bool {
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

/// Deduplicate packages by (name, version). Keeps first occurrence.
fn deduplicate_packages(packages: &[vlz_db::Package]) -> Vec<vlz_db::Package> {
    let mut seen = std::collections::HashSet::new();
    packages
        .iter()
        .filter(|p| seen.insert((p.name.as_str(), p.version.as_str())))
        .cloned()
        .collect()
}

/// Core entry point: runs the requested command and returns the exit code.
/// Caller is responsible for initialising the logger and for calling `process::exit(code)`.
pub async fn run(args: Cli) -> Result<i32> {
    // Resolve CLI cache TTL from subcommand (only `vlz db` and `vlz scan` have it).
    let cli_cache_ttl_secs = match &args.cmd {
        Commands::Db { cache_ttl_secs, .. } => *cache_ttl_secs,
        Commands::Scan { cache_ttl_secs, .. } => *cache_ttl_secs,
        _ => None,
    };

    // Load config from files + env + CLI for DB paths and TTL.
    let early_cfg = crate::config::load(
        args.config.as_deref(),
        crate::config::env_parallel(),
        crate::config::env_cache_db(),
        crate::config::env_ignore_db(),
        crate::config::env_cache_ttl_secs(),
        crate::config::env_min_score(),
        crate::config::env_min_count(),
        crate::config::env_exit_code_on_cve(),
        crate::config::env_fp_exit_code(),
        crate::config::env_backoff_base_ms(),
        crate::config::env_backoff_max_ms(),
        crate::config::env_max_retries(),
        None,
        None,
        None,
        cli_cache_ttl_secs,
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
        if let Some(parent) = cache_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).context("Creating cache directory")?;
            }
        }
        crate::registry::ensure_default_db_backend_with_path(cache_path, early_cfg.cache_ttl_secs)
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
    crate::registry::ensure_default_cve_provider();
    crate::registry::ensure_default_reporter();
    crate::registry::ensure_default_integrity_checker();

    let db_backend = {
        let mut backends = crate::registry::db_backends()
            .lock()
            .expect("DB_BACKENDS lock poisoned");
        if backends.is_empty() {
            error!("No DatabaseBackend implementation was registered.");
            return Err(anyhow!("No DatabaseBackend implementation was registered."));
        }
        let backend: Box<dyn vlz_db::DatabaseBackend + Send + Sync + 'static> = backends.remove(0);
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
            summary_file,
            provider,
            parallel: cli_parallel,
            cache_db: cli_cache_db,
            ignore_db: cli_ignore_db,
            cache_ttl_secs: cli_cache_ttl_secs,
            offline,
            benchmark,
            min_score: cli_min_score,
            min_count: cli_min_count,
            exit_code_on_cve: cli_exit_code_on_cve,
            fp_exit_code: cli_fp_exit_code,
            package_manager_required,
            backoff_base: cli_backoff_base,
            backoff_max: cli_backoff_max,
            max_retries: cli_max_retries,
        } => {
            let effective = crate::config::load(
                args.config.as_deref(),
                crate::config::env_parallel(),
                crate::config::env_cache_db(),
                crate::config::env_ignore_db(),
                crate::config::env_cache_ttl_secs(),
                crate::config::env_min_score(),
                crate::config::env_min_count(),
                crate::config::env_exit_code_on_cve(),
                crate::config::env_fp_exit_code(),
                crate::config::env_backoff_base_ms(),
                crate::config::env_backoff_max_ms(),
                crate::config::env_max_retries(),
                cli_parallel,
                cli_cache_db.as_deref(),
                cli_ignore_db.as_deref(),
                cli_cache_ttl_secs,
                offline,
                benchmark,
                cli_min_score,
                cli_min_count,
                cli_exit_code_on_cve,
                cli_fp_exit_code,
                package_manager_required,
                cli_backoff_base,
                cli_backoff_max,
                cli_max_retries,
            )
            .map_err(|e| {
                error!("{}", e);
                anyhow!(e)
            })?;
            let code = run_scan(
                root,
                format,
                summary_file,
                provider,
                effective,
                args.verbose,
                db_backend,
            )
            .await?;
            return Ok(code);
        }

        Commands::List => {
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
            return Ok(0);
        }

        Commands::Config { list, set } => {
            if let Some(pair) = set {
                let (key, value) = match crate::cli::parse_config_set_arg(pair.as_str()) {
                    Some((k, v)) => (k, v),
                    None => {
                        error!("Invalid --set argument; use KEY=VALUE (e.g. python.regex=\"^requirements\\.txt$\")");
                        return Err(anyhow!("Invalid --set argument; use KEY=VALUE"));
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
                    crate::config::env_cache_db(),
                    crate::config::env_ignore_db(),
                    crate::config::env_cache_ttl_secs(),
                    crate::config::env_min_score(),
                    crate::config::env_min_count(),
                    crate::config::env_exit_code_on_cve(),
                    crate::config::env_fp_exit_code(),
                    crate::config::env_backoff_base_ms(),
                    crate::config::env_backoff_max_ms(),
                    crate::config::env_max_retries(),
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
                .unwrap_or_default();
                write_stdout(&format!("parallel_queries = {}\n", cfg.parallel_queries));
                write_stdout(&format!("cache_ttl_secs = {}\n", cfg.cache_ttl_secs));
                write_stdout(&format!("min_score = {}\n", cfg.min_score));
                write_stdout(&format!("min_count = {}\n", cfg.min_count));
                write_stdout(&format!("backoff_base_ms = {}\n", cfg.backoff_base_ms));
                write_stdout(&format!("backoff_max_ms = {}\n", cfg.backoff_max_ms));
                write_stdout(&format!("max_retries = {}\n", cfg.max_retries));
                for (lang, re) in &cfg.language_regexes {
                    write_stdout(&format!("{}.regex = {}\n", lang, re));
                }
            }
            return Ok(0);
        }

        Commands::Db { sub, .. } => match sub {
            crate::cli::DbCommands::ListProviders => {
                let providers = crate::registry::providers()
                    .lock()
                    .expect("PROVIDERS lock poisoned");
                for p in providers.iter() {
                    write_stdout(&format!("{}\n", p.name()));
                }
                return Ok(0);
            }
            crate::cli::DbCommands::Stats => {
                let stats = db_backend.stats().await?;
                write_stdout(&format!(
                    "Cache entries: {}, hits: {}, misses: {}\n",
                    stats.cached_entries, stats.hits, stats.misses
                ));
                return Ok(0);
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
                    if let Err(e) = c.verify(db_backend.as_ref().as_ref()).await {
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
                return Ok(0);
            }
            crate::cli::DbCommands::Migrate => {
                write_stdout("Database migration completed (nothing to do)\n");
                return Ok(0);
            }
            crate::cli::DbCommands::Show { format, full } => {
                let entries = db_backend.list_entries(full).await?;
                if format.as_deref() == Some("json") {
                    write_stdout(&serde_json::to_string_pretty(&entries).unwrap());
                    write_stdout("\n");
                } else {
                    for e in &entries {
                        write_stdout(&format!(
                            "{}  ttl={}s  added_at={}  cve_count={}  \
                             cve_ids={:?}\n",
                            e.key, e.ttl_secs, e.added_at_secs, e.cve_count, e.cve_ids
                        ));
                        if let Some(ref raw) = e.raw_vulns {
                            write_stdout(&serde_json::to_string_pretty(raw).unwrap());
                            write_stdout("\n");
                        }
                    }
                    if entries.is_empty() {
                        write_stdout("(no cache entries)\n");
                    }
                }
                return Ok(0);
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
                    TtlSelector::Multiple(keys.split(',').map(|s| s.trim().to_string()).collect())
                } else {
                    error!("set-ttl requires one of: --entry KEY, --all, --pattern PATTERN, --entries KEY1,KEY2");
                    return Err(anyhow!(
                        "set-ttl requires one of: --entry, --all, --pattern, --entries"
                    ));
                };
                db_backend.set_ttl(selector, secs).await.map_err(|e| {
                    error!("set_ttl failed: {}", e);
                    anyhow!(e)
                })?;
                write_stdout("TTL updated.\n");
                return Ok(0);
            }
        },

        Commands::Fp { sub } => {
            let ignore_path = early_cfg
                .ignore_db
                .clone()
                .unwrap_or_else(crate::config::default_ignore_path);
            #[cfg(feature = "redb")]
            {
                let fp_db = vlz_db_redb::RedbIgnoreDb::with_path(ignore_path).map_err(|e| {
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
                        write_stdout(&format!("Marked {} as false positive\n", cve_id));
                    }
                    FpCommands::Unmark { cve_id } => {
                        fp_db.unmark(&cve_id).map_err(|e| {
                            error!("Failed to unmark: {}", e);
                            anyhow!(e)
                        })?;
                        write_stdout(&format!("Unmarked {}\n", cve_id));
                    }
                }
                return Ok(0);
            }
            #[cfg(not(feature = "redb"))]
            {
                error!("vlz fp requires the redb feature");
                return Err(anyhow!("vlz fp requires the redb feature"));
            }
        }

        Commands::Preload => {
            // FR-021: placeholder; future: connect to remote CVE DB and populate cache
            write_stdout(
                "vlz preload is a placeholder; cache is populated on demand during scan.\n",
            );
            return Ok(0);
        }

        Commands::Version => {
            write_stdout(&format!("verilyze {}\n", env!("CARGO_PKG_VERSION")));
            return Ok(0);
        }
    }
}

/// Runs the scan pipeline; returns the exit code to use (0, 1, 3, 4, 86, etc.).
async fn run_scan(
    root: Option<String>,
    format: String,
    summary_file: Vec<String>,
    provider: Option<String>,
    effective: crate::config::EffectiveConfig,
    _verbosity: u8,
    db_backend: Arc<Box<dyn vlz_db::DatabaseBackend + Send + Sync + 'static>>,
) -> Result<i32> {
    // -----------------------------------------------------------------
    // a) Resolve the root directory (default = current working dir)
    // -----------------------------------------------------------------
    let root_path = match root {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir().context("Unable to obtain current directory")?,
    };
    info!("Scanning root: {}", root_path.display());

    // -----------------------------------------------------------------
    // b) Choose the plug-ins we will use (first entry of each registry)
    // -----------------------------------------------------------------
    let finder: Box<dyn vlz_manifest_finder::ManifestFinder> =
        if effective.language_regexes.is_empty() {
            let mut f = crate::registry::finders()
                .lock()
                .expect("FINDERS lock poisoned");
            if f.is_empty() {
                error!("No ManifestFinder plug-in registered");
                return Err(anyhow!("No ManifestFinder plug-in registered"));
            }
            f.remove(0)
        } else {
            let patterns: Vec<String> = effective
                .language_regexes
                .iter()
                .map(|(_, r)| r.clone())
                .collect();
            #[cfg(feature = "python")]
            match vlz_python::PythonManifestFinder::with_patterns(patterns) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    error!("Invalid language regex in config: {}", e);
                    return Err(anyhow!("Invalid language regex in config: {}", e));
                }
            }
            #[cfg(not(feature = "python"))]
            {
                error!("Custom language regexes require a language plugin (e.g. python feature)");
                return Err(anyhow!("Custom language regexes require a language plugin"));
            }
        };

    let parser = {
        let mut p = crate::registry::parsers()
            .lock()
            .expect("PARSERS lock poisoned");
        if p.is_empty() {
            error!("No Parser plug-in registered");
            return Err(anyhow!("No Parser plug-in registered"));
        }
        p.remove(0)
    };

    let resolver = {
        let mut r = crate::registry::resolvers()
            .lock()
            .expect("RESOLVERS lock poisoned");
        if r.is_empty() {
            error!("No Resolver plug-in registered");
            return Err(anyhow!("No Resolver plug-in registered"));
        }
        r.remove(0)
    };

    // -----------------------------------------------------------------
    // b2) FR-024: if package manager required, check via resolver and exit 3 with hint if missing
    // -----------------------------------------------------------------
    if effective.package_manager_required {
        if !resolver.package_manager_available() {
            eprintln!(
                "Required package manager not found on PATH. {}",
                resolver.package_manager_hint()
            );
            return Ok(3);
        }
    }

    let provider_impl: Arc<Box<dyn vlz_cve_client::CveProvider + Send + Sync + 'static>> = {
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
        let wrapped = vlz_cve_client::RetryingCveProvider::new(inner, backoff_config);
        Arc::new(Box::new(wrapped))
    };

    let reporter: Box<dyn vlz_report::Reporter> = if format.eq_ignore_ascii_case("json") {
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
    let use_network = !(effective.offline || effective.benchmark);

    // -----------------------------------------------------------------
    // d) Scan phase - find manifest files
    // -----------------------------------------------------------------
    let manifests = finder
        .find(&root_path)
        .await
        .context("Failed during manifest discovery")?;
    info!("Found {} manifest(s)", manifests.len());

    // -----------------------------------------------------------------
    // e) Parse each manifest -> dependency graph, then resolve to packages
    // -----------------------------------------------------------------
    let mut all_packages = Vec::new();
    for mf in manifests {
        let graph = parser
            .parse(&mf)
            .await
            .with_context(|| format!("Parsing manifest {:?}", mf))?;
        let resolved = resolver
            .resolve(&graph)
            .await
            .with_context(|| format!("Resolving dependencies for {:?}", mf))?;
        all_packages.extend(resolved);
    }
    info!("Discovered {} package entries", all_packages.len());
    let all_packages_for_sbom = deduplicate_packages(&all_packages);

    // -----------------------------------------------------------------
    // f) For each package: try cache -> (optional) network -> store
    // -----------------------------------------------------------------
    let mut findings = Vec::new();
    let semaphore = Arc::new(Semaphore::new(effective_parallel));
    let mut handles = Vec::new();

    for pkg in all_packages {
        let db = db_backend.clone();
        let prov = provider_impl.clone();
        let sem = semaphore.clone();
        let permit = sem.acquire_owned().await.unwrap();

        let fut = async move {
            let _guard = permit;

            if let Some(cached) = db.as_ref().get(&pkg, prov.name()).await? {
                return Ok((pkg.clone(), cached));
            }

            if !use_network {
                return Err(anyhow!(
                    "CVE not found in cache, and unable to lookup CVE due to `--offline` argument."
                ));
            }

            let fetched = prov
                .as_ref()
                .fetch(&pkg)
                .await
                .with_context(|| format!("Fetching CVEs for {}@{}", pkg.name, pkg.version))?;
            db.as_ref()
                .put(&pkg, prov.name(), &fetched.raw_vulns, None)
                .await
                .with_context(|| format!("Storing cache for {}@{}", pkg.name, pkg.version))?;
            Ok((pkg.clone(), fetched.records))
        };

        handles.push(tokio::spawn(fut));
    }

    // -----------------------------------------------------------------
    // g) Gather results, apply false-positive filtering & severity map
    // -----------------------------------------------------------------
    let mut offline_cache_miss = false;
    let mut provider_fetch_failed = false;
    for h in handles {
        match h.await? {
            Ok((pkg, recs)) => {
                findings.push((pkg, recs));
            }
            Err(e) => {
                let msg = e.to_string();
                if effective.offline && msg.contains("--offline") {
                    offline_cache_miss = true;
                } else {
                    provider_fetch_failed = true;
                    error!("{}", e);
                    if _verbosity > 0 {
                        for cause in e.chain().skip(1) {
                            error!("  Caused by: {}", cause);
                        }
                    }
                }
            }
        }
    }
    if offline_cache_miss {
        let _ = db_backend.stats().await;
        eprintln!("CVE not found in cache, and unable to lookup CVE due to `--offline` argument.");
        return Ok(4);
    }
    if provider_fetch_failed {
        let _ = db_backend.stats().await;
        eprintln!("Unable to fetch CVE data from provider. Run with -v for details.");
        return Ok(5);
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
                .and_then(|db| db.marked_ids().ok())
                .unwrap_or_default()
        }
        #[cfg(not(feature = "redb"))]
        std::collections::HashSet::new()
    };
    let had_any_cves_before_fp_filter = findings.iter().map(|(_, r)| r.len()).sum::<usize>() > 0;
    let findings: Vec<(vlz_db::Package, Vec<vlz_db::CveRecord>)> = findings
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
        .filter(|cve| cve_meets_score_threshold(cve.cvss_score, effective.min_score))
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
    let severity_config = vlz_report::SeverityConfig::default();
    let report_findings: Vec<(vlz_db::Package, Vec<(vlz_db::CveRecord, vlz_db::Severity)>)> =
        findings
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
                (pkg, with_severity)
            })
            .collect();
    let report_data = vlz_report::ReportData {
        findings: report_findings,
        all_packages: Some(all_packages_for_sbom),
    };
    reporter
        .render(&report_data)
        .await
        .context("Failed while rendering the report")?;

    // -----------------------------------------------------------------
    // j) Emit optional secondary files (FR-008 --summary-file)
    // -----------------------------------------------------------------
    for spec in summary_file {
        let parts: Vec<_> = spec.splitn(2, ':').collect();
        if parts.len() != 2 {
            error!("Malformed --summary-file argument: {}", spec);
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
        write_stdout("{{\"benchmark\":{{\"duration_ms\":0,\"cpu_percent\":0,\"mem_mb\":0}}}}");
        write_stdout("\n");
    }

    // -----------------------------------------------------------------
    // l) Persist cache stats then return exit code
    // -----------------------------------------------------------------
    let _ = db_backend.stats().await;
    Ok(exit_code.into())
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
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
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
        assert_eq!(log_level_from_verbosity_count(100), log::LevelFilter::Trace);
    }

    #[test]
    fn is_broken_pipe_detects_io_error() {
        let e: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe").into();
        assert!(is_broken_pipe(&e));
    }

    #[test]
    fn is_broken_pipe_ignores_other_errors() {
        let e: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found").into();
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
    fn deduplicate_packages_removes_duplicates() {
        let packages = vec![
            vlz_db::Package {
                name: "foo".to_string(),
                version: "1.0".to_string(),
            },
            vlz_db::Package {
                name: "bar".to_string(),
                version: "2.0".to_string(),
            },
            vlz_db::Package {
                name: "foo".to_string(),
                version: "1.0".to_string(),
            },
        ];
        let deduped = deduplicate_packages(&packages);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].name, "foo");
        assert_eq!(deduped[1].name, "bar");
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
}
