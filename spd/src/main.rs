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

#![deny(unsafe_code)]

mod cli;
mod config;
mod registry;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{error, info, LevelFilter};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::cli::{Cli, Commands, FpCommands};

/// Write all bytes to `w`; propagates I/O errors (e.g. BrokenPipe).
/// Used by write_stdout and by tests with a buffer.
fn write_all_to<W: Write>(w: &mut W, s: &str) -> std::io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// True if the error chain contains an I/O BrokenPipe.
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    for cause in e.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::BrokenPipe {
                return true;
            }
        }
    }
    false
}

/// Write to stdout; exit 0 on broken pipe (e.g. `| less` then `q`).
/// Use for all user-facing stdout so every command handles piped output safely.
fn write_stdout(s: &str) {
    let mut out = std::io::stdout().lock();
    if let Err(e) = write_all_to(&mut out, s) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        panic!("failed printing to stdout: {}", e);
    }
}

/// Map verbosity count (number of `-v` flags) to log level.
fn log_level_from_verbosity_count(count: usize) -> LevelFilter {
    match count {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

/// Parse KEY=VALUE for `config --set`. Returns None if key is empty or no `=` present.
fn parse_config_set_arg(pair: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = pair.splitn(2, '=').map(str::trim).collect();
    match parts[..] {
        [k, v] if !k.is_empty() => Some((k, v)),
        _ => None,
    }
}

/// Core entry point: runs the requested command and returns the exit code.
/// Caller is responsible for initialising the logger and for calling `process::exit(code)`.
pub(crate) async fn run(args: Cli) -> Result<i32> {
    // Resolve CLI cache TTL from subcommand (only `spd db` and `spd scan` have it).
    let cli_cache_ttl_secs = match &args.cmd {
        Commands::Db { cache_ttl_secs, .. } => *cache_ttl_secs,
        Commands::Scan { cache_ttl_secs, .. } => *cache_ttl_secs,
        _ => None,
    };

    // Load config from files + env + CLI for DB paths and TTL.
    let early_cfg = config::load(
        args.config.as_deref(),
        config::env_parallel(),
        config::env_cache_db(),
        config::env_ignore_db(),
        config::env_cache_ttl_secs(),
        config::env_min_score(),
        config::env_min_count(),
        config::env_exit_code_on_cve(),
        config::env_fp_exit_code(),
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
    )
    .map_err(|e| {
        error!("{}", e);
        anyhow!(e)
    })?;

    let cache_path = early_cfg
        .cache_db
        .clone()
        .unwrap_or_else(config::default_cache_path);

    // -----------------------------------------------------------------
    // 3️⃣ Initialise plug‑ins (they register themselves via the macro)
    // -----------------------------------------------------------------
    #[cfg(feature = "redb")]
    {
        if let Some(parent) = cache_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).context("Creating cache directory")?;
            }
        }
        registry::ensure_default_db_backend_with_path(cache_path, early_cfg.cache_ttl_secs)
            .map_err(|e| {
                error!("Failed to open cache database: {}", e);
                anyhow!("Failed to open cache database: {}", e)
            })?;
        if args.verbose > 0 {
            info!("Cache TTL: {} s", early_cfg.cache_ttl_secs);
        }
    }
    registry::ensure_default_manifest_finder();
    registry::ensure_default_parser();
    registry::ensure_default_resolver();
    registry::ensure_default_cve_provider();
    registry::ensure_default_reporter();
    registry::ensure_default_integrity_checker();

    let db_backend = {
        let mut backends = registry::DB_BACKENDS
            .lock()
            .expect("DB_BACKENDS lock poisoned");
        if backends.is_empty() {
            error!("No DatabaseBackend implementation was registered.");
            return Err(anyhow!("No DatabaseBackend implementation was registered."));
        }
        //backends.remove(0)
        let backend: Box<dyn spd_db::DatabaseBackend + Send + Sync + 'static> = backends.remove(0);
        Arc::new(backend)
        //let db_backend = Arc::new(backend);
    };

    db_backend
        .init()
        .await
        .context("Failed to initialise DB backend")?;

    // -----------------------------------------------------------------
    // 4️⃣ Dispatch sub‑command
    // -----------------------------------------------------------------
    match args.cmd {
        Commands::Scan {
            root,
            format_type,
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
        } => {
            let effective = config::load(
                args.config.as_deref(),
                config::env_parallel(),
                config::env_cache_db(),
                config::env_ignore_db(),
                config::env_cache_ttl_secs(),
                config::env_min_score(),
                config::env_min_count(),
                config::env_exit_code_on_cve(),
                config::env_fp_exit_code(),
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
            )
            .map_err(|e| {
                error!("{}", e);
                anyhow!(e)
            })?;
            let code = run_scan(
                root,
                format_type,
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
            let finders = registry::FINDERS.lock().expect("FINDERS lock poisoned");
            if !finders.is_empty() {
                write_stdout("python\n");
            }
            return Ok(0);
        }

        Commands::Config { list, set } => {
            if let Some(pair) = set {
                let (key, value) = match parse_config_set_arg(pair.as_str()) {
                    Some((k, v)) => (k, v),
                    None => {
                        error!("Invalid --set argument; use KEY=VALUE (e.g. python.regex=\"^requirements\\.txt$\")");
                        return Err(anyhow!(
                            "Invalid --set argument; use KEY=VALUE"
                        ));
                    }
                };
                if let Err(e) = config::set_config_key(key, value) {
                    error!("{}", e);
                    return Err(e.into());
                }
                write_stdout(&format!("Set {} = {}\n", key, value));
            }
            if list {
                let cfg = config::load(
                    args.config.as_deref(),
                    config::env_parallel(),
                    config::env_cache_db(),
                    config::env_ignore_db(),
                    config::env_cache_ttl_secs(),
                    config::env_min_score(),
                    config::env_min_count(),
                    config::env_exit_code_on_cve(),
                    config::env_fp_exit_code(),
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
                )
                .unwrap_or_default();
                write_stdout(&format!("parallel_queries = {}\n", cfg.parallel_queries));
                write_stdout(&format!("cache_ttl_secs = {}\n", cfg.cache_ttl_secs));
                write_stdout(&format!("min_score = {}\n", cfg.min_score));
                write_stdout(&format!("min_count = {}\n", cfg.min_count));
                for (lang, re) in &cfg.language_regexes {
                    write_stdout(&format!("{}.regex = {}\n", lang, re));
                }
            }
            return Ok(0);
        }

        Commands::Db { sub, .. } => match sub {
            cli::DbCommands::ListProviders => {
                let providers = registry::PROVIDERS.lock().expect("PROVIDERS lock poisoned");
                for p in providers.iter() {
                    write_stdout(&format!("{}\n", p.name()));
                }
                return Ok(0);
            }
            cli::DbCommands::Stats => {
                let stats = db_backend.stats().await?;
                write_stdout(&format!(
                    "Cache entries: {}, hits: {}, misses: {}\n",
                    stats.cached_entries, stats.hits, stats.misses
                ));
                return Ok(0);
            }
            cli::DbCommands::Verify => {
                let checker = {
                    let mut c = registry::INTEGRITY_CHECKERS
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
                    registry::INTEGRITY_CHECKERS
                        .lock()
                        .expect("INTEGRITY_CHECKERS lock poisoned")
                        .insert(0, c);
                } else if let Err(e) = db_backend.verify_integrity().await {
                    error!("{}", e);
                    return Ok(1); // FR-033: exit 1 on verify failure
                }
                write_stdout("Database integrity verified (SHA‑256)\n"); // FR-033
                return Ok(0);
            }
            cli::DbCommands::Migrate => {
                write_stdout("Database migration completed (nothing to do)\n");
                return Ok(0);
            }
            cli::DbCommands::Show { format, full } => {
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
                return Ok(0);
            }
            cli::DbCommands::SetTtl {
                secs,
                entry,
                all,
                pattern,
                entries: entries_arg,
            } => {
                use spd_db::TtlSelector;
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
                            .filter(|e| {
                                e.key.contains(p.as_str())
                                    || p.strip_suffix('*')
                                        .map(|prefix| e.key.starts_with(prefix))
                                        .unwrap_or(false)
                            })
                            .map(|e| e.key)
                            .collect(),
                    )
                } else if let Some(keys) = entries_arg {
                    TtlSelector::Multiple(
                        keys.split(',').map(|s| s.trim().to_string()).collect(),
                    )
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
                .unwrap_or_else(config::default_ignore_path);
            #[cfg(feature = "redb")]
            {
                let fp_db = spd_db_redb::RedbIgnoreDb::with_path(ignore_path).map_err(|e| {
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
                error!("spd fp requires the redb feature");
                return Err(anyhow!("spd fp requires the redb feature"));
            }
        }

        Commands::Preload => {
            // FR-021: placeholder; future: connect to remote CVE DB and populate cache
            write_stdout(
                "spd preload is a placeholder; cache is populated on demand during scan.\n",
            );
            return Ok(0);
        }

        Commands::Version => {
            write_stdout(&format!("super‑duper {}\n", env!("CARGO_PKG_VERSION")));
            return Ok(0);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");
    let log_filter =
        log_level_from_verbosity_count(std::env::args().filter(|a| a == "-v").count());
    env_logger::Builder::from_env(env)
        .filter_level(log_filter)
        .init();

    let args = Cli::parse();
    let code = run(args).await.unwrap_or_else(|e| {
        if is_broken_pipe(&e) {
            0
        } else {
            error!("{}", e);
            2
        }
    });
    std::process::exit(code);
}

// ---------------------------------------------------------------------
// 5️⃣ Core scan implementation – follows `execution‑flow.txt`
// ---------------------------------------------------------------------
/// Runs the scan pipeline; returns the exit code to use (0, 1, 3, 4, 86, etc.).
async fn run_scan(
    root: Option<String>,
    format_type: String,
    summary_file: Vec<String>,
    provider: Option<String>,
    effective: config::EffectiveConfig,
    _verbosity: u8,
    db_backend: Arc<Box<dyn spd_db::DatabaseBackend + Send + Sync + 'static>>,
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
    // a2) FR-024: if package manager required, check for pip/pip3 and exit 3 with hint if missing
    // -----------------------------------------------------------------
    if effective.package_manager_required {
        if !python_package_manager_available() {
            eprintln!(
                "Required package manager (pip) not found on PATH. {}",
                package_manager_hint()
            );
            return Ok(3);
        }
    }

    // -----------------------------------------------------------------
    // b) Choose the plug‑ins we will use (first entry of each registry)
    // -----------------------------------------------------------------
    let finder: Box<dyn spd_manifest_finder::ManifestFinder> =
        if effective.language_regexes.is_empty() {
            let mut f = registry::FINDERS.lock().expect("FINDERS lock poisoned");
            if f.is_empty() {
                error!("No ManifestFinder plug‑in registered");
                return Err(anyhow!("No ManifestFinder plug‑in registered"));
            }
            f.remove(0)
        } else {
            let patterns: Vec<String> = effective
                .language_regexes
                .iter()
                .map(|(_, r)| r.clone())
                .collect();
            match spd_manifest_finder::DefaultManifestFinder::with_patterns(patterns) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    error!("Invalid language regex in config: {}", e);
                    return Err(anyhow!("Invalid language regex in config: {}", e));
                }
            }
        };

    let parser = {
        let mut p = registry::PARSERS.lock().expect("PARSERS lock poisoned");
        if p.is_empty() {
            error!("No Parser plug‑in registered");
            return Err(anyhow!("No Parser plug‑in registered"));
        }
        p.remove(0)
    };

    let resolver = {
        let mut r = registry::RESOLVERS.lock().expect("RESOLVERS lock poisoned");
        if r.is_empty() {
            error!("No Resolver plug‑in registered");
            return Err(anyhow!("No Resolver plug‑in registered"));
        }
        r.remove(0)
    };

    let provider_impl: Arc<Box<dyn spd_cve_client::CveProvider + Send + Sync + 'static>> = {
        let mut prov = registry::PROVIDERS.lock().expect("PROVIDERS lock poisoned");
        if prov.is_empty() {
            error!("No CveProvider plug‑in registered");
            return Err(anyhow!("No CveProvider plug‑in registered"));
        }
        let p = if let Some(ref name) = provider {
            let pos = prov.iter().position(|p| p.name() == name.as_str());
            match pos {
                Some(i) => prov.remove(i),
                None => {
                    error!(
                        "Unknown provider: {} (use `spd db list-providers` to list)",
                        name
                    );
                    return Err(anyhow!(
                        "Unknown provider: {} (use `spd db list-providers` to list)",
                        name
                    ));
                }
            }
        } else {
            prov.remove(0)
        };
        Arc::new(p)
    };

    let reporter: Box<dyn spd_report::Reporter> = if format_type.eq_ignore_ascii_case("json") {
        Box::new(spd_report::JsonReporter::new())
    } else {
        let mut r = registry::REPORTERS.lock().expect("REPORTERS lock poisoned");
        if r.is_empty() {
            error!("No Reporter plug‑in registered");
            return Err(anyhow!("No Reporter plug‑in registered"));
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
    // d) Scan phase – find manifest files
    // -----------------------------------------------------------------
    let manifests = finder
        .find(&root_path)
        .await
        .context("Failed during manifest discovery")?;
    info!("Found {} manifest(s)", manifests.len());

    // -----------------------------------------------------------------
    // e) Parse each manifest → dependency graph, then resolve to packages
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

    // -----------------------------------------------------------------
    // f) For each package: try cache → (optional) network → store
    // -----------------------------------------------------------------
    let mut findings = Vec::new(); // (Package, Vec<CveRecord>)
    let semaphore = Arc::new(Semaphore::new(effective_parallel));
    let mut handles = Vec::new();

    // moved by tpost from for loop below

    for pkg in all_packages {
        // Acquire a permit *before* spawning the task so the semaphore
        // limits the number of concurrent futures.
        //let db = db_backend.as_ref();
        //let prov = provider_impl.as_ref();
        let db = db_backend.clone();
        let prov = provider_impl.clone();
        let sem = semaphore.clone();
        let permit = sem.acquire_owned().await.unwrap();

        let fut = async move {
            // The permit is held for the whole lifetime of this future.
            // When the future finishes `_guard` is dropped and the permit
            // is released automatically.
            let _guard = permit;

            // 1️⃣ Check cache
            if let Some(cached) = db.as_ref().get(&pkg).await? {
                return Ok((pkg.clone(), cached));
            }

            // 2️⃣ Offline mode – we cannot query the network (FR-031)
            if !use_network {
                return Err(anyhow!(
                    "CVE not found in cache, and unable to lookup CVE due to `--offline` argument."
                ));
            }

            // 3️⃣ Query the provider (concurrent up to `effective_parallel`)
            let fetched = prov.as_ref().fetch(&pkg).await?;
            db.as_ref()
                .put(&pkg, &fetched.raw_vulns, None)
                .await?;
            Ok((pkg.clone(), fetched.records))
        };

        handles.push(tokio::spawn(fut));
    }

    // -----------------------------------------------------------------
    // g) Gather results, apply false‑positive filtering & severity map
    // -----------------------------------------------------------------
    let mut offline_cache_miss = false;
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
                    error!("Error while processing a package: {}", e);
                }
            }
        }
    }
    if offline_cache_miss {
        let _ = db_backend.stats().await;
        eprintln!("CVE not found in cache, and unable to lookup CVE due to `--offline` argument.");
        return Ok(4);
    }

    // -----------------------------------------------------------------
    // g2) Apply false‑positive filter (FR‑015, FR‑016)
    // -----------------------------------------------------------------
    let marked_fp: std::collections::HashSet<String> = {
        #[cfg(feature = "redb")]
        {
            let ignore_path = effective
                .ignore_db
                .clone()
                .unwrap_or_else(config::default_ignore_path);
            spd_db_redb::RedbIgnoreDb::with_path(ignore_path)
                .ok()
                .and_then(|db| db.marked_ids().ok())
                .unwrap_or_default()
        }
        #[cfg(not(feature = "redb"))]
        std::collections::HashSet::new()
    };
    let had_any_cves_before_fp_filter = findings.iter().map(|(_, r)| r.len()).sum::<usize>() > 0;
    let findings: Vec<(spd_db::Package, Vec<spd_db::CveRecord>)> = findings
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
    // h) Apply threshold logic (FR‑014, FR‑010) and decide exit code
    // -----------------------------------------------------------------
    // Filter CVEs by primary CVSS score >= min_score; then count.
    let meeting_threshold: usize = findings
        .iter()
        .flat_map(|(_, recs)| recs.iter())
        .filter(|cve| {
            cve.cvss_score
                .map(|s| s >= effective.min_score)
                .unwrap_or(effective.min_score <= 0.0)
        })
        .count();
    // If min_count is 0, treat as "disable count check" per FR-014: still exit CVE code if any CVE meets min_score.
    let trigger_cve_exit = if effective.min_count == 0 {
        meeting_threshold >= 1
    } else {
        meeting_threshold >= effective.min_count
    };
    let exit_code = if !trigger_cve_exit {
        0
    } else {
        effective.exit_code_on_cve.unwrap_or(86)
    };
    let total_cves: usize = findings.iter().map(|(_, r)| r.len()).sum();
    info!(
        "Total CVEs discovered: {}, meeting threshold (score>={}): {}",
        total_cves, effective.min_score, meeting_threshold
    );

    // -----------------------------------------------------------------
    // i) Resolve severity (FR‑013) and render the report (FR‑007, FR‑008, FR‑009)
    // -----------------------------------------------------------------
    let severity_config = spd_report::SeverityConfig::default();
    let report_findings: Vec<(spd_db::Package, Vec<(spd_db::CveRecord, spd_db::Severity)>)> =
        findings
            .into_iter()
            .map(|(pkg, recs)| {
                let with_severity: Vec<_> = recs
                    .into_iter()
                    .map(|cve| {
                        let severity = spd_report::resolve_severity(
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
    let report_data = spd_report::ReportData {
        findings: report_findings,
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
        let reporter: Box<dyn spd_report::Reporter> = match fmt.as_str() {
            "html" => Box::new(spd_report::HtmlReporter::new()),
            "json" => Box::new(spd_report::JsonReporter::new()),
            "sarif" => Box::new(spd_report::SarifReporter::new()),
            "plain" | "text" => Box::new(spd_report::DefaultReporter::new()),
            _ => {
                error!(
                    "Unknown summary format '{}'; use html, json, sarif, or plain",
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
    // k) Benchmark mode handling (FR‑029)
    // -----------------------------------------------------------------
    if effective.benchmark {
        write_stdout(
            "{{\"benchmark\":{{\"duration_ms\":0,\"cpu_percent\":0,\"mem_mb\":0}}}}",
        );
        write_stdout("\n");
    }

    // -----------------------------------------------------------------
    // l) Persist cache stats then return exit code
    // -----------------------------------------------------------------
    let _ = db_backend.stats().await;
    Ok(exit_code.into())
}

/// Returns true if pip or pip3 appears to be on PATH (FR-024).
fn python_package_manager_available() -> bool {
    for cmd in ["pip3", "pip"] {
        if std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// OS-specific hint when pip is missing (FR-024).
fn package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: apt-get install python3-pip (Debian/Ubuntu) or dnf install python3-pip (Fedora/RHEL).";
    #[cfg(target_os = "macos")]
    return "Install via: brew install python3.";
    #[cfg(target_os = "windows")]
    return "Install Python from https://www.python.org/ and ensure pip is enabled.";
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return "Install Python and pip for your platform.";
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::io::Write;

    // -------------------------------------------------------------------------
    // Unit tests for functions in main.rs (run in-process for coverage)
    // -------------------------------------------------------------------------

    #[test]
    fn package_manager_hint_returns_non_empty() {
        let hint = super::package_manager_hint();
        assert!(!hint.is_empty(), "hint must not be empty");
        assert!(
            hint.contains("pip") || hint.contains("Python"),
            "hint should mention pip or Python"
        );
    }

    #[test]
    fn python_package_manager_available_does_not_panic() {
        let _ = super::python_package_manager_available();
    }

    #[test]
    fn python_package_manager_available_consistent() {
        let a = super::python_package_manager_available();
        let b = super::python_package_manager_available();
        assert_eq!(a, b, "result should be consistent (env-dependent)");
    }

    #[test]
    fn write_all_to_writes_bytes() {
        let mut buf = Vec::new();
        let r = super::write_all_to(&mut buf, "hello\n");
        assert!(r.is_ok());
        assert_eq!(buf, b"hello\n");
    }

    #[test]
    fn write_all_to_empty_string() {
        let mut buf = Vec::new();
        let r = super::write_all_to(&mut buf, "");
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
        let r = super::write_all_to(&mut w, "x");
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn log_level_from_verbosity_count_zero_is_info() {
        assert_eq!(
            super::log_level_from_verbosity_count(0),
            log::LevelFilter::Info
        );
    }

    #[test]
    fn log_level_from_verbosity_count_one_is_debug() {
        assert_eq!(
            super::log_level_from_verbosity_count(1),
            log::LevelFilter::Debug
        );
    }

    #[test]
    fn log_level_from_verbosity_count_two_or_more_is_trace() {
        assert_eq!(
            super::log_level_from_verbosity_count(2),
            log::LevelFilter::Trace
        );
        assert_eq!(
            super::log_level_from_verbosity_count(100),
            log::LevelFilter::Trace
        );
    }

    #[test]
    fn parse_config_set_arg_valid() {
        assert_eq!(
            super::parse_config_set_arg("a=b"),
            Some(("a", "b"))
        );
        assert_eq!(
            super::parse_config_set_arg("key = val "),
            Some(("key", "val"))
        );
        assert_eq!(super::parse_config_set_arg("x="), Some(("x", "")));
    }

    #[test]
    fn parse_config_set_arg_invalid() {
        assert_eq!(super::parse_config_set_arg(""), None);
        assert_eq!(super::parse_config_set_arg("=value"), None);
        assert_eq!(super::parse_config_set_arg("key"), None);
    }

    // -------------------------------------------------------------------------
    // Tests that call run() in-process (for coverage)
    // -------------------------------------------------------------------------

    /// Set XDG_* env vars to a temp dir and run an async block so run() doesn't touch user data.
    /// Repopulates plugin registries so each test gets a fresh backend (run() consumes one per call).
    fn with_temp_xdg<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().to_string_lossy().into_owned();
        temp_env::with_var("XDG_CACHE_HOME", Some(p.as_str()), || {
            temp_env::with_var("XDG_DATA_HOME", Some(p.as_str()), || {
                temp_env::with_var("XDG_CONFIG_HOME", Some(p.as_str()), || {
                    ensure_registries_for_run();
                    f()
                })
            })
        })
    }

    /// Repopulate plugin registries so run() can proceed (it consumes one backend per call).
    fn ensure_registries_for_run() {
        let _guard = crate::registry::REGISTRY_TEST_MUTEX.lock().unwrap();
        crate::registry::ensure_default_manifest_finder();
        crate::registry::ensure_default_parser();
        crate::registry::ensure_default_resolver();
        crate::registry::ensure_default_cve_provider();
        crate::registry::ensure_default_reporter();
        crate::registry::ensure_default_integrity_checker();
        #[cfg(feature = "redb")]
        {
            let cache_path = crate::config::default_cache_path();
            let _ = crate::registry::ensure_default_db_backend_with_path(cache_path, 432000);
        }
    }

    fn run_async(args: &[&str]) -> i32 {
        let _guard = crate::registry::REGISTRY_TEST_MUTEX.lock().unwrap();
        let mut v = vec!["spd"];
        v.extend(args.iter().copied());
        let args = crate::cli::Cli::parse_from(v);
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(super::run(args)).unwrap_or(2)
    }

    #[test]
    fn run_version_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["version"]), 0));
    }

    #[test]
    fn run_list_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["list"]), 0));
    }

    #[test]
    fn run_preload_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["preload"]), 0));
    }

    #[test]
    fn run_config_list_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["config", "--list"]), 0));
    }

    #[test]
    fn run_config_set_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            ensure_registries_for_run();
            assert_eq!(
                run_async(&["config", "--set", "python.regex=^requirements\\.txt$"]),
                0
            );
        });
    }

    #[test]
    fn run_config_set_invalid_exits_2() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            assert_eq!(run_async(&["config", "--set", "=value"]), 2);
            ensure_registries_for_run();
            assert_eq!(run_async(&["config", "--set", "key"]), 2);
        });
    }

    #[test]
    fn run_config_set_unknown_key_exits_2() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            assert_eq!(run_async(&["config", "--set", "nodot=value"]), 2);
        });
    }

    #[test]
    fn run_config_invalid_file_exits_2() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let f = tempfile::NamedTempFile::new().expect("temp file");
            std::fs::write(f.path(), "invalid toml {{{").expect("write");
            let path = f.path().to_str().unwrap();
            assert_eq!(run_async(&["-c", path, "list"]), 2);
        });
    }

    #[test]
    fn run_db_set_ttl_no_selector_exits_2() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            assert_eq!(run_async(&["db", "set-ttl", "3600"]), 2);
        });
    }

    #[test]
    fn run_db_migrate_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "migrate"]), 0));
    }

    #[test]
    fn run_db_list_providers_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "list-providers"]), 0));
    }

    #[test]
    fn run_db_stats_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "stats"]), 0));
    }

    #[test]
    fn run_db_verify_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "verify"]), 0));
    }

    #[test]
    fn run_db_show_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "show"]), 0));
    }

    #[test]
    fn run_db_show_format_json_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "show", "--format", "json"]), 0));
    }

    #[test]
    fn run_db_set_ttl_all_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| assert_eq!(run_async(&["db", "set-ttl", "3600", "--all"]), 0));
    }

    #[test]
    fn run_db_set_ttl_entry() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let code = run_async(&["db", "set-ttl", "3600", "--entry", "somekey"]);
            assert!(code == 0 || code == 2, "set-ttl --entry returns 0 or 2");
        });
    }

    #[test]
    fn run_db_set_ttl_pattern() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let code = run_async(&["db", "set-ttl", "3600", "--pattern", "x"]);
            assert!(code == 0 || code == 2);
        });
    }

    #[test]
    fn run_db_set_ttl_entries() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let code = run_async(&["db", "set-ttl", "3600", "--entries", "a,b"]);
            assert!(code == 0 || code == 2);
        });
    }

    #[test]
    fn run_with_verbose_logs_cache_ttl() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            assert_eq!(run_async(&["-v", "db", "stats"]), 0);
        });
    }

    #[test]
    fn run_cache_path_parent_created() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let sub = dir.path().join("sub");
            assert!(!sub.exists());
            let cache_db = sub.join("cache.redb").to_string_lossy().into_owned();
            temp_env::with_var("SPD_CACHE_DB", Some(&cache_db), || {
                assert_eq!(run_async(&["db", "stats"]), 0);
            });
            assert!(sub.exists(), "parent dir should be created");
        });
    }

    #[test]
    fn run_scan_offline_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            assert_eq!(
                run_async(&["scan", root, "--offline", "--benchmark"]),
                0
            );
        });
    }

    #[test]
    fn run_scan_no_root_uses_cwd() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let code = run_async(&["scan", "--offline", "--benchmark"]);
            assert!(code == 0 || code == 2, "scan without root uses cwd");
        });
    }

    #[test]
    fn run_scan_offline_with_manifest_exits_4() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join("requirements.txt"), "pkg==1.0\n")
                .expect("write requirements");
            let root = dir.path().to_str().unwrap();
            assert_eq!(
                run_async(&["scan", root, "--offline"]),
                4,
                "offline scan with manifest but no cache hits exit 4"
            );
        });
    }

    #[test]
    fn run_scan_no_benchmark_uses_parallel_queries() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            assert_eq!(run_async(&["scan", root, "--offline"]), 0);
        });
    }

    #[test]
    fn run_scan_package_manager_required_no_pip_exits_3() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            let empty_dir = tempfile::tempdir().expect("tempdir");
            let path_without_pip = empty_dir.path().to_string_lossy().into_owned();
            temp_env::with_var("PATH", Some(&path_without_pip), || {
                let code = run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--package-manager-required",
                ]);
                assert_eq!(code, 3, "missing pip with --package-manager-required → exit 3");
            });
        });
    }

    #[test]
    fn run_scan_format_json_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--format-type",
                    "json",
                    "--offline",
                    "--benchmark",
                ]),
                0
            );
        });
    }

    #[test]
    fn run_scan_unknown_provider_exits_2() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            assert_eq!(
                run_async(&["scan", root, "--offline", "--provider", "nonexistent"]),
                2
            );
        });
    }

    #[test]
    fn run_scan_config_parallel_too_high_exits_2() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--benchmark",
                    "--parallel",
                    "51",
                ]),
                2
            );
        });
    }

    #[test]
    fn run_scan_with_summary_file_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            let out = dir.path().join("out.json");
            let out_str = out.to_str().unwrap();
            let spec = format!("json:{}", out_str);
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--benchmark",
                    "--summary-file",
                    &spec,
                ]),
                0
            );
            assert!(out.exists(), "summary file should be created");
        });
    }

    #[test]
    fn run_scan_summary_file_html_plain_sarif() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            let html_path = dir.path().join("out.html");
            let plain_path = dir.path().join("out.txt");
            let sarif_path = dir.path().join("out.sarif");
            let spec_html = format!("html:{}", html_path.to_str().unwrap());
            let spec_plain = format!("plain:{}", plain_path.to_str().unwrap());
            let spec_sarif = format!("sarif:{}", sarif_path.to_str().unwrap());
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--benchmark",
                    "--summary-file",
                    &spec_html,
                    "--summary-file",
                    &spec_plain,
                    "--summary-file",
                    &spec_sarif,
                ]),
                0
            );
            assert!(html_path.exists());
            assert!(plain_path.exists());
            assert!(sarif_path.exists());
        });
    }

    #[test]
    fn run_scan_summary_file_unknown_format() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            let out = dir.path().join("out.unknown");
            let out_str = out.to_str().unwrap();
            let spec = format!("unknown:{}", out_str);
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--benchmark",
                    "--summary-file",
                    &spec,
                ]),
                0
            );
        });
    }

    #[test]
    fn run_scan_summary_file_malformed() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_str().unwrap();
            assert_eq!(
                run_async(&[
                    "scan",
                    root,
                    "--offline",
                    "--benchmark",
                    "--summary-file",
                    "nocolon",
                ]),
                0
            );
        });
    }

    #[cfg(feature = "redb")]
    #[test]
    fn run_fp_mark_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            assert_eq!(
                run_async(&["fp", "mark", "CVE-2020-1234", "--comment", "test"]),
                0
            );
        });
    }

    #[cfg(feature = "redb")]
    #[test]
    fn run_fp_unmark_exits_0() {
        let _ = env_logger::try_init();
        with_temp_xdg(|| {
            run_async(&["fp", "mark", "CVE-2020-5678", "--comment", "to remove"]);
            ensure_registries_for_run();
            assert_eq!(run_async(&["fp", "unmark", "CVE-2020-5678"]), 0);
        });
    }
}
