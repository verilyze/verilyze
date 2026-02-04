//! spd – the core binary for the Super‑Duper SCA tool.
//! (Only the semaphore handling and a few imports were fixed.)

mod cli;
mod registry;

use anyhow::{anyhow, Context, Result}; // ← added `anyhow!`
use clap::Parser;
use log::{error, info, LevelFilter};
use std::sync::Arc; // ← needed for Semaphore sharing
use tokio::sync::Semaphore; // ← Tokio semaphore

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

    // -----------------------------------------------------------------
    // 3️⃣ Initialise plug‑ins (they register themselves via the macro)
    // -----------------------------------------------------------------
    #[cfg(feature = "redb")]
    registry::ensure_default_db_backend();
    registry::ensure_default_manifest_finder();
    registry::ensure_default_parser();
    registry::ensure_default_cve_provider();
    registry::ensure_default_reporter();

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
            parallel,
            offline,
            benchmark,
        } => {
            run_scan(
                root,
                format_type,
                summary_file,
                provider,
                parallel,
                offline,
                benchmark,
                args.verbose,
                db_backend,
            )
            .await?;
        }

        Commands::Config { list } => {
            if list {
                println!("Effective configuration (placeholder)");
            }
        }

        Commands::Db { sub } => match sub {
            cli::DbCommands::Stats => {
                let stats = db_backend.stats().await?;
                println!(
                    "Cache entries: {}, hits: {}, misses: {}",
                    stats.cached_entries, stats.hits, stats.misses
                );
            }
            cli::DbCommands::Verify => {
                db_backend.verify_integrity().await?;
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
    parallel: usize,
    offline: bool,
    benchmark: bool,
    verbosity: u8,
    //db_backend: Box<dyn spd_db::DatabaseBackend>,
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

    let provider_impl = {
        let mut prov = registry::PROVIDERS.lock().expect("PROVIDERS lock poisoned");
        if prov.is_empty() {
            error!("No CveProvider plug‑in registered");
            std::process::exit(2);
        }
        //    prov.remove(0)
        let p: Box<dyn spd_cve_client::CveProvider + Send + Sync + 'static> = prov.remove(0);
        Arc::new(p)
    };
    let provider_impl = Arc::new(provider_impl);

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
    let effective_parallel = if benchmark { 1 } else { parallel };
    let use_network = !(offline || benchmark);

    // -----------------------------------------------------------------
    // d) Scan phase – find manifest files
    // -----------------------------------------------------------------
    let manifests = finder
        .find(&root_path)
        .await
        .context("Failed during manifest discovery")?;
    info!("Found {} manifest(s)", manifests.len());

    // -----------------------------------------------------------------
    // e) Parse each manifest → dependency graph
    // -----------------------------------------------------------------
    let mut all_packages = Vec::new();
    for mf in manifests {
        let graph = parser
            .parse(&mf)
            .await
            .with_context(|| format!("Parsing manifest {:?}", mf))?;
        all_packages.extend(graph.packages);
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
                // #region agent log
                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open("/home/uno/projects/super-duper/.cursor/debug.log") {
                    use std::io::Write;
                    let pk = format!("{}::{}", pkg.name, pkg.version).replace('"', "\\\"");
                    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
                    let _ = writeln!(f, "{{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"H1\",\"location\":\"spd/main.rs:cache\",\"message\":\"cache_hit\",\"data\":{{\"pkg\":\"{}\",\"cached_count\":{}}},\"timestamp\":{}}}", pk, cached.len(), ts);
                }
                // #endregion
                return Ok((pkg.clone(), cached));
            }

            // 2️⃣ Offline mode – we cannot query the network
            if !use_network {
                return Err(anyhow!("CVE not in cache and offline mode is active"));
            }

            // 3️⃣ Query the provider (concurrent up to `effective_parallel`)
            let fetched = prov.as_ref().fetch(&pkg).await?;
            // #region agent log
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open("/home/uno/projects/super-duper/.cursor/debug.log") {
                use std::io::Write;
                let pk = format!("{}::{}", pkg.name, pkg.version).replace('"', "\\\"");
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
                let _ = writeln!(f, "{{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"H1\",\"location\":\"spd/main.rs:fetch\",\"message\":\"fetch_used\",\"data\":{{\"pkg\":\"{}\",\"fetched_count\":{}}},\"timestamp\":{}}}", pk, fetched.records.len(), ts);
            }
            // #endregion
            db.as_ref().put(&pkg, &fetched.raw_vulns).await?;
            Ok((pkg.clone(), fetched.records))
        };

        handles.push(tokio::spawn(fut));
    }

    // -----------------------------------------------------------------
    // g) Gather results, apply false‑positive filtering & severity map
    // -----------------------------------------------------------------
    for h in handles {
        match h.await? {
            Ok((pkg, recs)) => {
                // ----- false‑positive filtering (stub) -----
                // Real implementation would consult the FP DB.
                // ------------------------------------------------

                // ----- severity mapping (stub) -----
                // Real implementation would map CVSS v3 scores to the enum.
                // ------------------------------------------------

                findings.push((pkg, recs));
            }
            Err(e) => {
                if offline {
                    info!("Offline – skipping network lookup: {}", e);
                } else {
                    error!("Error while processing a package: {}", e);
                }
            }
        }
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
    let report_findings: Vec<(spd_db::Package, Vec<(spd_db::CveRecord, spd_db::Severity)>)> = findings
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
    if benchmark {
        println!("{{\"benchmark\":{{\"duration_ms\":0,\"cpu_percent\":0,\"mem_mb\":0}}}}");
    }

    // -----------------------------------------------------------------
    // l) Final exit
    // -----------------------------------------------------------------
    std::process::exit(exit_code);
}
