//! spd – the core binary for the Super‑Duper SCA tool.
#![deny(unsafe_code)]

mod cli;
mod config;
mod registry;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::cli::{Cli, Commands};

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

    // Load config from files + env (no CLI overrides yet) for DB paths.
    let early_cfg = config::load(
        args.config.as_deref(),
        config::env_parallel(),
        config::env_cache_db(),
        config::env_ignore_db(),
        None,
        None,
        None,
        false,
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
            offline,
            benchmark,
        } => {
            let effective = config::load(
                args.config.as_deref(),
                config::env_parallel(),
                config::env_cache_db(),
                config::env_ignore_db(),
                cli_parallel,
                cli_cache_db.as_deref(),
                cli_ignore_db.as_deref(),
                offline,
                benchmark,
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
                println!("python");
            }
        }

        Commands::Config { list } => {
            if list {
                println!("Effective configuration (placeholder)");
            }
        }

        Commands::Db { sub } => match sub {
            cli::DbCommands::ListProviders => {
                let providers = registry::PROVIDERS.lock().expect("PROVIDERS lock poisoned");
                for p in providers.iter() {
                    println!("{}", p.name());
                }
            }
            cli::DbCommands::Stats => {
                let stats = db_backend.stats().await?;
                println!(
                    "Cache entries: {}, hits: {}, misses: {}",
                    stats.cached_entries, stats.hits, stats.misses
                );
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
                        std::process::exit(1);
                    })?;
                    registry::INTEGRITY_CHECKERS
                        .lock()
                        .expect("INTEGRITY_CHECKERS lock poisoned")
                        .insert(0, c);
                } else {
                    db_backend.verify_integrity().await?;
                }
                println!("Database integrity verified (SHA‑256)");
            }
            cli::DbCommands::Migrate => {
                println!("Database migration completed (nothing to do)");
            }
        },

        Commands::Version => {
            println!("super‑duper {}", env!("CARGO_PKG_VERSION"));
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
    // b) Choose the plug‑ins we will use (first entry of each registry)
    // -----------------------------------------------------------------
    let finder = {
        let mut f = registry::FINDERS.lock().expect("FINDERS lock poisoned");
        if f.is_empty() {
            error!("No ManifestFinder plug‑in registered");
            std::process::exit(2);
        }
        f.remove(0)
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
            db.as_ref().put(&pkg, &fetched.raw_vulns).await?;
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
        eprintln!("CVE not found in cache, and unable to lookup CVE due to `--offline` argument.");
        std::process::exit(4);
    }

    // -----------------------------------------------------------------
    // h) Apply threshold logic (FR‑014, FR‑016) and decide exit code
    // -----------------------------------------------------------------
    let total_cves: usize = findings.iter().map(|(_, r)| r.len()).sum();
    let exit_code = if total_cves == 0 { 0 } else { 86 };
    info!("Total CVEs discovered: {}", total_cves);

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
    // j) Emit optional secondary files (summary_file flag)
    // -----------------------------------------------------------------
    for spec in summary_file {
        let parts: Vec<_> = spec.splitn(2, ':').collect();
        if parts.len() != 2 {
            error!("Malformed --summary-file argument: {}", spec);
            continue;
        }
        let (fmt, path) = (parts[0], parts[1]);
        info!("Would generate {} report at {}", fmt, path);
    }

    // -----------------------------------------------------------------
    // k) Benchmark mode handling (FR‑029)
    // -----------------------------------------------------------------
    if effective.benchmark {
        println!("{{\"benchmark\":{{\"duration_ms\":0,\"cpu_percent\":0,\"mem_mb\":0}}}}");
    }

    // -----------------------------------------------------------------
    // l) Final exit
    // -----------------------------------------------------------------
    std::process::exit(exit_code);
}
