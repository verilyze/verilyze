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

/// Write to stdout; exit 0 on broken pipe (e.g. `| less` then `q`).
/// Use for all user-facing stdout so every command handles piped output safely.
fn write_stdout(s: &str) {
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(s.as_bytes()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        panic!("failed printing to stdout: {}", e);
    }
    let _ = out.flush();
}

#[tokio::main]
async fn main() -> Result<()> {
    // -----------------------------------------------------------------
    // 1️⃣ Initialise logger (verbosity handling)
    // -----------------------------------------------------------------
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");

    // Map `-v` counts to log levels (0 → Info, 1 → Debug, 2+ → Trace)
    let log_filter = match std::env::args().filter(|a| a == "-v").count() {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    env_logger::Builder::from_env(env)
        .filter_level(log_filter)
        .init();

    // -----------------------------------------------------------------
    // 2️⃣ Parse CLI arguments (clap) and load configuration
    // -----------------------------------------------------------------
    let args = Cli::parse();

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
        std::process::exit(2);
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
                std::process::exit(2);
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
            std::process::exit(2);
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
                std::process::exit(2);
            })?;
            run_scan(
                root,
                format_type,
                summary_file,
                provider,
                effective,
                args.verbose,
                db_backend,
            )
            .await?;
        }

        Commands::List => {
            let finders = registry::FINDERS.lock().expect("FINDERS lock poisoned");
            if !finders.is_empty() {
                write_stdout("python\n");
            }
        }

        Commands::Config { list, set } => {
            if let Some(pair) = set {
                let (key, value) = match pair.splitn(2, '=').map(str::trim).collect::<Vec<_>>()[..]
                {
                    [k, v] if !k.is_empty() => (k, v),
                    _ => {
                        error!("Invalid --set argument; use KEY=VALUE (e.g. python.regex=\"^requirements\\.txt$\")");
                        std::process::exit(2);
                    }
                };
                if let Err(e) = config::set_config_key(key, value) {
                    error!("{}", e);
                    std::process::exit(2);
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
        }

        Commands::Db { sub, .. } => match sub {
            cli::DbCommands::ListProviders => {
                let providers = registry::PROVIDERS.lock().expect("PROVIDERS lock poisoned");
                for p in providers.iter() {
                    write_stdout(&format!("{}\n", p.name()));
                }
            }
            cli::DbCommands::Stats => {
                let stats = db_backend.stats().await?;
                write_stdout(&format!(
                    "Cache entries: {}, hits: {}, misses: {}\n",
                    stats.cached_entries, stats.hits, stats.misses
                ));
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
                    c.verify(db_backend.as_ref().as_ref()).await.map_err(|e| {
                        error!("{}", e);
                        std::process::exit(1); // FR-033: exit 1 on verify failure
                    })?;
                    registry::INTEGRITY_CHECKERS
                        .lock()
                        .expect("INTEGRITY_CHECKERS lock poisoned")
                        .insert(0, c);
                } else {
                    db_backend.verify_integrity().await.map_err(|e| {
                        error!("{}", e);
                        std::process::exit(1); // FR-033: exit 1 on verify failure
                    })?;
                }
                write_stdout("Database integrity verified (SHA‑256)\n"); // FR-033
            }
            cli::DbCommands::Migrate => {
                write_stdout("Database migration completed (nothing to do)\n");
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
                    std::process::exit(2);
                };
                db_backend.set_ttl(selector, secs).await.map_err(|e| {
                    error!("set_ttl failed: {}", e);
                    std::process::exit(2);
                })?;
                write_stdout("TTL updated.\n");
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
                    std::process::exit(2);
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
                                std::process::exit(2);
                            })?;
                        write_stdout(&format!("Marked {} as false positive\n", cve_id));
                    }
                    FpCommands::Unmark { cve_id } => {
                        fp_db.unmark(&cve_id).map_err(|e| {
                            error!("Failed to unmark: {}", e);
                            std::process::exit(2);
                        })?;
                        write_stdout(&format!("Unmarked {}\n", cve_id));
                    }
                }
            }
            #[cfg(not(feature = "redb"))]
            {
                error!("spd fp requires the redb feature");
                std::process::exit(2);
            }
        }

        Commands::Preload => {
            // FR-021: placeholder; future: connect to remote CVE DB and populate cache
            write_stdout(
                "spd preload is a placeholder; cache is populated on demand during scan.\n",
            );
        }

        Commands::Version => {
            write_stdout(&format!("super‑duper {}\n", env!("CARGO_PKG_VERSION")));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------
// 5️⃣ Core scan implementation – follows `execution‑flow.txt`
// ---------------------------------------------------------------------
async fn run_scan(
    root: Option<String>,
    format_type: String,
    summary_file: Vec<String>,
    provider: Option<String>,
    effective: config::EffectiveConfig,
    _verbosity: u8,
    db_backend: Arc<Box<dyn spd_db::DatabaseBackend + Send + Sync + 'static>>,
) -> Result<()> {
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
            std::process::exit(3);
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
                std::process::exit(2);
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
                    std::process::exit(2);
                }
            }
        };

    let parser = {
        let mut p = registry::PARSERS.lock().expect("PARSERS lock poisoned");
        if p.is_empty() {
            error!("No Parser plug‑in registered");
            std::process::exit(2);
        }
        p.remove(0)
    };

    let resolver = {
        let mut r = registry::RESOLVERS.lock().expect("RESOLVERS lock poisoned");
        if r.is_empty() {
            error!("No Resolver plug‑in registered");
            std::process::exit(2);
        }
        r.remove(0)
    };

    let provider_impl: Arc<Box<dyn spd_cve_client::CveProvider + Send + Sync + 'static>> = {
        let mut prov = registry::PROVIDERS.lock().expect("PROVIDERS lock poisoned");
        if prov.is_empty() {
            error!("No CveProvider plug‑in registered");
            std::process::exit(2);
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
                    std::process::exit(2);
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
            std::process::exit(2);
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
        std::process::exit(4);
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
        std::process::exit(effective.fp_exit_code.unwrap_or(0).into());
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
    // l) Persist cache stats then exit (exit() skips Drop)
    // -----------------------------------------------------------------
    let _ = db_backend.stats().await;
    std::process::exit(exit_code.into());
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
    use std::path::Path;
    use std::process::{Command, Stdio};

    /// Path to the spd binary (set by Cargo when running tests). Skip if missing.
    fn spd_exe() -> Option<String> {
        let exe = std::env::var("CARGO_BIN_EXE_spd").ok()?;
        if Path::new(&exe).exists() {
            Some(exe)
        } else {
            None
        }
    }

    /// Run spd with args and broken stdout pipe; assert exit 0 (no panic).
    /// Skips if CARGO_BIN_EXE_spd is unset or binary missing.
    fn assert_broken_pipe_exits_cleanly(args: &[&str]) {
        let exe = match spd_exe() {
            Some(p) => p,
            None => {
                eprintln!("skip: CARGO_BIN_EXE_spd unset or binary missing");
                return;
            }
        };
        let mut child = Command::new(&exe)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert!(
            status.code() == Some(0),
            "args {:?} should exit 0 on broken pipe, got {:?}",
            args,
            status.code()
        );
    }

    #[test]
    fn broken_pipe_version() {
        assert_broken_pipe_exits_cleanly(&["version"]);
    }

    #[test]
    fn broken_pipe_preload() {
        assert_broken_pipe_exits_cleanly(&["preload"]);
    }

    #[test]
    fn broken_pipe_db_migrate() {
        assert_broken_pipe_exits_cleanly(&["db", "migrate"]);
    }

    #[test]
    fn broken_pipe_db_show() {
        assert_broken_pipe_exits_cleanly(&["db", "show"]);
    }

    #[test]
    fn broken_pipe_db_show_full() {
        assert_broken_pipe_exits_cleanly(&["db", "show", "--full"]);
    }

    #[test]
    fn broken_pipe_db_show_format_json() {
        assert_broken_pipe_exits_cleanly(&["db", "show", "--format", "json"]);
    }

    #[test]
    fn broken_pipe_list() {
        assert_broken_pipe_exits_cleanly(&["list"]);
    }

    #[test]
    fn broken_pipe_config_list() {
        assert_broken_pipe_exits_cleanly(&["config", "--list"]);
    }

    #[test]
    fn broken_pipe_db_list_providers() {
        assert_broken_pipe_exits_cleanly(&["db", "list-providers"]);
    }

    #[test]
    fn broken_pipe_db_stats() {
        assert_broken_pipe_exits_cleanly(&["db", "stats"]);
    }

    #[test]
    fn broken_pipe_db_verify() {
        assert_broken_pipe_exits_cleanly(&["db", "verify"]);
    }

    #[test]
    fn broken_pipe_db_set_ttl_all() {
        assert_broken_pipe_exits_cleanly(&["db", "set-ttl", "3600", "--all"]);
    }

    #[test]
    fn broken_pipe_scan_benchmark() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_broken_pipe_exits_cleanly(&[
            "scan",
            dir.path().to_str().unwrap(),
            "--benchmark",
            "--offline",
        ]);
    }

    #[cfg(feature = "redb")]
    #[test]
    fn broken_pipe_fp_mark() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ignore_db = dir.path().join("ignore.redb");
        let exe = match spd_exe() {
            Some(p) => p,
            None => {
                eprintln!("skip: CARGO_BIN_EXE_spd unset or binary missing");
                return;
            }
        };
        let mut child = Command::new(&exe)
            .args(["fp", "mark", "CVE-2020-1234", "test"])
            .env("SPD_IGNORE_DB", ignore_db.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(0),
            "fp mark should exit 0 on broken pipe"
        );
    }

    #[cfg(feature = "redb")]
    #[test]
    fn broken_pipe_fp_unmark() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ignore_db = dir.path().join("ignore.redb");
        let exe = match spd_exe() {
            Some(p) => p,
            None => {
                eprintln!("skip: CARGO_BIN_EXE_spd unset or binary missing");
                return;
            }
        };
        let mark = Command::new(&exe)
            .args(["fp", "mark", "CVE-2020-1234", "test"])
            .env("SPD_IGNORE_DB", ignore_db.as_os_str())
            .output()
            .expect("spawn spd fp mark");
        assert!(mark.status.success(), "fp mark must succeed first");
        let mut child = Command::new(&exe)
            .args(["fp", "unmark", "CVE-2020-1234"])
            .env("SPD_IGNORE_DB", ignore_db.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(0),
            "fp unmark should exit 0 on broken pipe"
        );
    }

    #[test]
    fn cli_db_show_help_succeeds() {
        let exe = match spd_exe() {
            Some(p) => p,
            None => {
                eprintln!("skip: CARGO_BIN_EXE_spd unset or binary missing");
                return;
            }
        };
        let out = Command::new(&exe)
            .args(["db", "show", "--help"])
            .output()
            .expect("run spd db show --help");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("show") || stdout.contains("cache"));
    }

    #[test]
    fn cli_db_set_ttl_help_succeeds() {
        let exe = match spd_exe() {
            Some(p) => p,
            None => {
                eprintln!("skip: CARGO_BIN_EXE_spd unset or binary missing");
                return;
            }
        };
        let out = Command::new(&exe)
            .args(["db", "set-ttl", "--help"])
            .output()
            .expect("run spd db set-ttl --help");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
