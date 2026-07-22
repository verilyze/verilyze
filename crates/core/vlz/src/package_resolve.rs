// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use log::{error, info};
use tokio::sync::Semaphore;
use vlz_db::Package;
use vlz_manifest_finder::ManifestFinder;
use vlz_manifest_parser::{Parser, ResolveContext, Resolver};
use vlz_reachability::PackageContext;
use vlz_report::ManifestCoverageEntry;

use crate::cache_warm::deduplicate_packages;
use crate::config::EffectiveConfig;
use crate::scan::ManifestTaskOutcome;

fn normalized_exclude_dir_names(entries: &[String]) -> HashSet<String> {
    entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn should_skip_dir(path: &Path, exclude: &HashSet<String>) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| exclude.contains(name))
        .unwrap_or(false)
}

type ManifestDiscoveryResult =
    (HashMap<String, Vec<PathBuf>>, Vec<(PathBuf, Vec<String>)>);

fn discover_manifests_one_pass(
    root: &Path,
    exclude_dirs: &HashSet<String>,
    #[cfg(feature = "python")] lock_file_allowlist: &[String],
) -> std::io::Result<ManifestDiscoveryResult> {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    #[cfg(feature = "python")]
    let mut python_manifests: Vec<PathBuf> = Vec::new();
    #[cfg(feature = "python")]
    let mut python_locks: Vec<PathBuf> = Vec::new();
    #[cfg(feature = "python")]
    let mut python_lock_dirs: HashSet<PathBuf> = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                let path = entry.path();
                if !should_skip_dir(&path, exclude_dirs) {
                    stack.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            #[cfg(feature = "python")]
            {
                if vlz_python::PYTHON_MANIFEST_NAMES.contains(&name) {
                    python_manifests.push(entry.path());
                    continue;
                }
                if vlz_python::is_python_lock_file(name) {
                    if let Some(parent) = entry.path().parent() {
                        python_lock_dirs.insert(parent.to_path_buf());
                    }
                    if vlz_python::lock_name_matches_allowlist(
                        name,
                        lock_file_allowlist,
                    ) {
                        python_locks.push(entry.path());
                    }
                    continue;
                }
            }
            #[cfg(feature = "rust")]
            if name == vlz_rust::RUST_MANIFEST_NAME {
                out.entry("rust".to_string())
                    .or_default()
                    .push(entry.path());
                continue;
            }
            #[cfg(feature = "go")]
            if name == vlz_go::GO_MANIFEST_NAME {
                out.entry("go".to_string()).or_default().push(entry.path());
            }
        }
    }
    #[cfg(feature = "python")]
    {
        if !lock_file_allowlist.is_empty() {
            for dir in &python_lock_dirs {
                vlz_python::verify_lock_allowlist_for_dir(
                    dir,
                    lock_file_allowlist,
                )
                .map_err(|message| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        message,
                    )
                })?;
            }
        }
        let orphans =
            vlz_python::filter_orphan_locks(&python_manifests, &python_locks);
        python_manifests.extend(orphans);
        python_manifests.sort();
        python_manifests.dedup();
        out.insert("python".to_string(), python_manifests);
    }
    for manifests in out.values_mut() {
        manifests.sort();
    }
    #[cfg(feature = "python")]
    let orphan_multi_lock_warnings =
        vlz_python::orphan_multi_lock_warning_dirs(
            out.get("python").map_or(&[][..], |v| v.as_slice()),
            &python_locks,
        );
    #[cfg(not(feature = "python"))]
    let orphan_multi_lock_warnings = Vec::new();
    Ok((out, orphan_multi_lock_warnings))
}

/// Output of manifest discovery, parse, and resolve for a scan root.
#[derive(Debug)]
pub struct ResolvePackagesOutput {
    pub root_path: PathBuf,
    pub exclude_dirs: HashSet<String>,
    pub packages_with_manifests: Vec<(Package, PathBuf, String)>,
    pub pkg_declarations:
        HashMap<Package, Vec<vlz_db::PackageDeclarationLocation>>,
    pub pkg_contexts: HashMap<Package, PackageContext>,
    pub packages_to_check: Vec<Package>,
    pub manifest_coverage: Vec<ManifestCoverageEntry>,
    pub skip_cve_phase: bool,
    pub package_manager_missing: bool,
}

/// Whether cross-language resolution may run concurrently.
fn parallel_languages_enabled(effective: &EffectiveConfig, n: usize) -> bool {
    !effective.fail_fast && !effective.benchmark && n > 1
}

/// Per-language discovery + resolve result before ordered aggregation.
struct LanguagePhaseResult {
    outcomes: Vec<ManifestTaskOutcome>,
    deferred_messages: Vec<String>,
}

/// Parse and resolve manifests for one language under a shared resolution semaphore.
async fn resolve_language_manifests(
    language: String,
    manifests: Vec<PathBuf>,
    parser: &dyn Parser,
    resolver: &dyn Resolver,
    resolve_ctx: &ResolveContext,
    resolution_semaphore: Arc<Semaphore>,
) -> Vec<ManifestTaskOutcome> {
    let tasks: Vec<_> = manifests
        .into_iter()
        .map(|mf| {
            let language = language.clone();
            let ctx = resolve_ctx.clone();
            let resolution_sem = resolution_semaphore.clone();
            async move {
                match parser.parse(&mf).await {
                    Ok(graph) => {
                        let _permit = resolution_sem.acquire().await;
                        match resolver.resolve(&graph, &ctx).await {
                            Ok(resolved) => ManifestTaskOutcome::Success {
                                resolved,
                                manifest_path: mf,
                                language,
                            },
                            Err(error) => ManifestTaskOutcome::ResolveFailed {
                                manifest_path: mf,
                                language,
                                error,
                            },
                        }
                    }
                    Err(error) => ManifestTaskOutcome::ParseFailed {
                        manifest_path: mf,
                        language,
                        error,
                    },
                }
            }
        })
        .collect();
    let mut outcomes = futures::future::join_all(tasks).await;
    outcomes.sort_by(|a, b| a.manifest_path().cmp(b.manifest_path()));
    outcomes
}

async fn discover_manifests_for_language(
    language: &str,
    root_path: &Path,
    finder: &dyn ManifestFinder,
    effective: &EffectiveConfig,
    precomputed: Option<Vec<PathBuf>>,
) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let mut deferred_messages = Vec::new();
    let used_finder_discovery = precomputed.is_none();
    let mut manifests = if let Some(paths) = precomputed {
        paths
    } else if language == "python" {
        #[cfg(feature = "python")]
        {
            if effective.language_regexes.is_empty() {
                vlz_python::PythonManifestFinder::new()
                    .with_lock_file_allowlist(
                        effective.python_lock_files.clone(),
                    )
                    .find(root_path)
                    .await
                    .context("Failed during manifest discovery")?
            } else {
                finder
                    .find(root_path)
                    .await
                    .context("Failed during manifest discovery")?
            }
        }
        #[cfg(not(feature = "python"))]
        Vec::new()
    } else {
        finder
            .find(root_path)
            .await
            .context("Failed during manifest discovery")?
    };
    manifests.sort();
    #[cfg(feature = "python")]
    if language == "python" && used_finder_discovery {
        let lock_paths: Vec<PathBuf> = manifests
            .iter()
            .filter(|p| vlz_python::manifest_is_lock_file(p))
            .cloned()
            .collect();
        let manifest_paths: Vec<PathBuf> = manifests
            .iter()
            .filter(|p| !vlz_python::manifest_is_lock_file(p))
            .cloned()
            .collect();
        for (dir, lock_names) in vlz_python::orphan_multi_lock_warning_dirs(
            &manifest_paths,
            &lock_paths,
        ) {
            deferred_messages.push(
                vlz_manifest_parser::format_multi_lock_warning(
                    &dir.display().to_string(),
                    &lock_names,
                ),
            );
        }
    }
    #[cfg(not(feature = "python"))]
    let _ = used_finder_discovery;
    Ok((manifests, deferred_messages))
}

struct LanguagePhaseArgs<'a> {
    language: String,
    precomputed: Option<Vec<PathBuf>>,
    root_path: &'a Path,
    finder: &'a dyn ManifestFinder,
    parser: &'a dyn Parser,
    resolver: &'a dyn Resolver,
    effective: &'a EffectiveConfig,
    resolve_ctx: &'a ResolveContext,
    resolution_semaphore: Arc<Semaphore>,
}

async fn run_language_phase(
    args: LanguagePhaseArgs<'_>,
) -> Result<LanguagePhaseResult> {
    let LanguagePhaseArgs {
        language,
        precomputed,
        root_path,
        finder,
        parser,
        resolver,
        effective,
        resolve_ctx,
        resolution_semaphore,
    } = args;
    let language_discovery_started_at = Instant::now();
    let (manifests, mut deferred_messages) = discover_manifests_for_language(
        &language,
        root_path,
        finder,
        effective,
        precomputed,
    )
    .await?;
    let discovery_ms = language_discovery_started_at.elapsed().as_millis();
    info!(
        "Found {} manifest(s) for {} in {} ms",
        manifests.len(),
        language,
        discovery_ms
    );
    let manifest_count = manifests.len();
    if manifest_count > 1 {
        deferred_messages.push(format!(
            "Resolving {manifest_count} {language} manifest(s)..."
        ));
    }
    let outcomes = resolve_language_manifests(
        language,
        manifests,
        parser,
        resolver,
        resolve_ctx,
        resolution_semaphore,
    )
    .await;
    Ok(LanguagePhaseResult {
        outcomes,
        deferred_messages,
    })
}

fn finish_resolve_output(
    root_path: PathBuf,
    exclude_dirs: HashSet<String>,
    packages_with_manifests: Vec<(Package, PathBuf, String)>,
    pkg_declarations: HashMap<
        Package,
        Vec<vlz_db::PackageDeclarationLocation>,
    >,
    manifest_coverage: Vec<ManifestCoverageEntry>,
    skip_cve_phase: bool,
    discovery_started_at: Instant,
) -> ResolvePackagesOutput {
    info!(
        "Manifest discovery finished in {} ms",
        discovery_started_at.elapsed().as_millis()
    );
    info!(
        "Discovered {} package entries",
        packages_with_manifests.len()
    );

    let mut pkg_contexts: HashMap<Package, PackageContext> = HashMap::new();
    for (pkg, path, language) in &packages_with_manifests {
        let entry = pkg_contexts.entry(pkg.clone()).or_default();
        entry.languages.insert(language.clone());
        entry.manifest_paths.push(path.clone());
    }
    let all_packages: Vec<Package> = packages_with_manifests
        .iter()
        .map(|(p, _, _)| p.clone())
        .collect();
    let packages_to_check = deduplicate_packages(&all_packages);
    info!(
        "Checking {} unique packages for CVEs",
        packages_to_check.len()
    );

    ResolvePackagesOutput {
        root_path,
        exclude_dirs,
        packages_with_manifests,
        pkg_declarations,
        pkg_contexts,
        packages_to_check,
        manifest_coverage,
        skip_cve_phase,
        package_manager_missing: false,
    }
}

/// Mutable aggregation state for folding per-language outcomes.
struct OutcomeSink<'a> {
    root_path: &'a Path,
    verbosity: u8,
    effective: &'a EffectiveConfig,
    packages_with_manifests: &'a mut Vec<(Package, PathBuf, String)>,
    pkg_declarations:
        &'a mut HashMap<Package, Vec<vlz_db::PackageDeclarationLocation>>,
    multi_lock_warned: &'a mut HashSet<PathBuf>,
    manifest_coverage: &'a mut Vec<ManifestCoverageEntry>,
}

/// Fold outcomes into coverage / packages; returns true if fail_fast tripped.
fn apply_language_outcomes(
    outcomes: Vec<ManifestTaskOutcome>,
    sink: &mut OutcomeSink<'_>,
) -> bool {
    let mut fail_fast_tripped = false;
    for outcome in outcomes {
        match outcome {
            ManifestTaskOutcome::Success {
                resolved,
                manifest_path,
                language,
            } => {
                sink.manifest_coverage.push(
                    crate::scan::coverage_entry_success(
                        manifest_path.clone(),
                        language.clone(),
                        &resolved,
                    ),
                );
                if resolved.resolved_lock_paths.len() > 1
                    && let Some(dir) = manifest_path.parent()
                    && sink.multi_lock_warned.insert(dir.to_path_buf())
                {
                    let lock_names: Vec<String> = resolved
                        .resolved_lock_paths
                        .iter()
                        .filter_map(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .map(str::to_string)
                        })
                        .collect();
                    eprintln!(
                        "{}",
                        vlz_manifest_parser::format_multi_lock_warning(
                            &dir.display().to_string(),
                            &lock_names,
                        )
                    );
                }
                vlz_manifest_parser::merge_declaration_maps(
                    sink.pkg_declarations,
                    resolved.package_declarations,
                );
                for pkg in resolved.packages {
                    if let Some(sources) =
                        resolved.package_source_paths.get(&pkg)
                    {
                        for path in sources {
                            sink.packages_with_manifests.push((
                                pkg.clone(),
                                path.clone(),
                                language.clone(),
                            ));
                        }
                    } else {
                        sink.packages_with_manifests.push((
                            pkg,
                            manifest_path.clone(),
                            language.clone(),
                        ));
                    }
                }
            }
            ManifestTaskOutcome::ParseFailed {
                manifest_path,
                language,
                error,
            } => {
                sink.manifest_coverage.push(
                    crate::scan::coverage_entry_parse_failure(
                        manifest_path.clone(),
                        language,
                        &error,
                    ),
                );
                crate::scan::log_manifest_failure(
                    &manifest_path,
                    &error,
                    sink.verbosity,
                    Some(sink.root_path),
                );
                if sink.effective.fail_fast {
                    fail_fast_tripped = true;
                    break;
                }
            }
            ManifestTaskOutcome::ResolveFailed {
                manifest_path,
                language,
                error,
            } => {
                sink.manifest_coverage.push(
                    crate::scan::coverage_entry_resolution_failure(
                        manifest_path.clone(),
                        language,
                        &error,
                    ),
                );
                crate::scan::log_manifest_failure(
                    &manifest_path,
                    &error,
                    sink.verbosity,
                    Some(sink.root_path),
                );
                if sink.effective.fail_fast {
                    fail_fast_tripped = true;
                    break;
                }
            }
        }
    }
    fail_fast_tripped
}

/// Discover manifests under `root`, parse, and resolve dependencies.
pub async fn resolve_packages_for_path(
    root: Option<String>,
    effective: &EffectiveConfig,
    verbosity: u8,
) -> Result<ResolvePackagesOutput> {
    let root_path = match root {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir()
            .context("Unable to obtain current directory")?,
    };
    info!("Scanning root: {}", root_path.display());

    let mut finders = Vec::new();
    let mut parsers = Vec::new();
    let mut resolvers = Vec::new();

    if effective.language_regexes.is_empty() {
        std::mem::swap(
            &mut *crate::registry::finders().lock().unwrap(),
            &mut finders,
        );
        std::mem::swap(
            &mut *crate::registry::parsers().lock().unwrap(),
            &mut parsers,
        );
        std::mem::swap(
            &mut *crate::registry::resolvers().lock().unwrap(),
            &mut resolvers,
        );
    } else {
        let patterns: Vec<String> = effective
            .language_regexes
            .iter()
            .map(|(_, r)| r.clone())
            .collect();
        let first_lang =
            effective.language_regexes.first().map(|(l, _)| l.as_str());
        #[cfg(feature = "python")]
        if first_lang != Some("rust") && first_lang != Some("go") {
            match vlz_python::PythonManifestFinder::with_patterns(
                patterns.clone(),
            ) {
                Ok(f) => finders.push(Box::new(f.with_lock_file_allowlist(
                    effective.python_lock_files.clone(),
                ))),
                Err(e) => {
                    error!("Invalid language regex in config: {}", e);
                    return Err(anyhow!(
                        "Invalid language regex in config: {}",
                        e
                    ));
                }
            }
        }
        #[cfg(feature = "rust")]
        if first_lang == Some("rust")
            || (finders.is_empty() && first_lang != Some("go"))
        {
            match vlz_rust::RustManifestFinder::with_patterns(patterns.clone())
            {
                Ok(f) => finders.push(Box::new(f)),
                Err(e) => {
                    error!("Invalid language regex in config: {}", e);
                    return Err(anyhow!(
                        "Invalid language regex in config: {}",
                        e
                    ));
                }
            }
        }
        #[cfg(feature = "go")]
        if first_lang == Some("go") || finders.is_empty() {
            match vlz_go::GoManifestFinder::with_patterns(patterns) {
                Ok(f) => finders.push(Box::new(f)),
                Err(e) => {
                    error!("Invalid language regex in config: {}", e);
                    return Err(anyhow!(
                        "Invalid language regex in config: {}",
                        e
                    ));
                }
            }
        }
        #[cfg(not(any(
            feature = "python",
            feature = "rust",
            feature = "go"
        )))]
        {
            error!(
                "Custom language regexes require a language plugin (e.g. python, rust, or go feature)"
            );
            return Err(anyhow!(
                "Custom language regexes require a language plugin"
            ));
        }
        let mut p = crate::registry::parsers().lock().unwrap();
        let mut r = crate::registry::resolvers().lock().unwrap();
        let m = finders.len().min(p.len()).min(r.len());
        for _ in 0..m {
            parsers.push(p.remove(0));
            resolvers.push(r.remove(0));
        }
    }

    resolve_packages_with_plugins(
        root_path, effective, verbosity, finders, parsers, resolvers,
    )
    .await
}

/// Plugin-injectable resolve path (used by production and concurrency tests).
pub(crate) async fn resolve_packages_with_plugins(
    root_path: PathBuf,
    effective: &EffectiveConfig,
    verbosity: u8,
    mut finders: Vec<Box<dyn ManifestFinder>>,
    mut parsers: Vec<Box<dyn Parser>>,
    mut resolvers: Vec<Box<dyn Resolver>>,
) -> Result<ResolvePackagesOutput> {
    let n = finders.len().min(parsers.len()).min(resolvers.len());
    if n == 0 {
        error!("No ManifestFinder, Parser, or Resolver plug-in registered");
        return Err(anyhow!(
            "No ManifestFinder, Parser, or Resolver plug-in registered"
        ));
    }

    if effective.package_manager_required {
        for r in resolvers.iter().take(n) {
            if !r.package_manager_available() {
                eprintln!(
                    "Required package manager not found on PATH. {}",
                    r.package_manager_hint()
                );
                return Ok(ResolvePackagesOutput {
                    root_path,
                    exclude_dirs: HashSet::new(),
                    packages_with_manifests: Vec::new(),
                    pkg_declarations: HashMap::new(),
                    pkg_contexts: HashMap::new(),
                    packages_to_check: Vec::new(),
                    manifest_coverage: Vec::new(),
                    skip_cve_phase: false,
                    package_manager_missing: true,
                });
            }
        }
    }

    let effective_resolution_parallel = if effective.benchmark {
        1
    } else {
        effective.parallel_resolutions.max(1)
    };

    let discovery_started_at = Instant::now();
    let exclude_dirs =
        normalized_exclude_dir_names(&effective.scan_exclude_dirs);
    let mut packages_with_manifests: Vec<(Package, PathBuf, String)> =
        Vec::new();
    let mut pkg_declarations: HashMap<
        Package,
        Vec<vlz_db::PackageDeclarationLocation>,
    > = HashMap::new();
    let mut multi_lock_warned: HashSet<PathBuf> = HashSet::new();
    let mut manifest_coverage: Vec<ManifestCoverageEntry> = Vec::new();
    let mut skip_cve_phase = false;
    let resolve_ctx = ResolveContext {
        keep_ephemeral_venv: effective.keep_ephemeral_venv,
        skip_pip_resolution: effective.offline || effective.benchmark,
        benchmark_mode: effective.benchmark,
        allow_dependency_code_execution: effective
            .allow_dependency_code_execution,
        allow_direct_only_fallback: effective.allow_direct_only_fallback,
        python_lock_files: effective.python_lock_files.clone(),
    };
    let can_use_shared_discovery = effective.language_regexes.is_empty()
        && finders.iter().take(n).all(|finder| {
            matches!(finder.language_name(), "python" | "rust" | "go")
        });

    let (mut manifests_by_language, orphan_multi_lock_warnings) =
        if can_use_shared_discovery {
            discover_manifests_one_pass(
                &root_path,
                &exclude_dirs,
                #[cfg(feature = "python")]
                &effective.python_lock_files,
            )
            .context("Failed during manifest discovery")?
        } else {
            (HashMap::new(), Vec::new())
        };

    for (dir, lock_names) in &orphan_multi_lock_warnings {
        eprintln!(
            "{}",
            vlz_manifest_parser::format_multi_lock_warning(
                &dir.display().to_string(),
                lock_names,
            )
        );
    }

    let resolution_semaphore =
        Arc::new(Semaphore::new(effective_resolution_parallel));
    let parallel_languages = parallel_languages_enabled(effective, n);

    struct LanguageJob {
        language: String,
        precomputed: Option<Vec<PathBuf>>,
        finder: Box<dyn ManifestFinder>,
        parser: Box<dyn Parser>,
        resolver: Box<dyn Resolver>,
    }

    finders.truncate(n);
    parsers.truncate(n);
    resolvers.truncate(n);

    let mut jobs: Vec<LanguageJob> = Vec::with_capacity(n);
    for ((finder, parser), resolver) in
        finders.into_iter().zip(parsers).zip(resolvers)
    {
        let language = finder.language_name().to_string();
        let precomputed = if can_use_shared_discovery {
            Some(manifests_by_language.remove(&language).unwrap_or_default())
        } else {
            None
        };
        jobs.push(LanguageJob {
            language,
            precomputed,
            finder,
            parser,
            resolver,
        });
    }

    {
        let mut sink = OutcomeSink {
            root_path: root_path.as_path(),
            verbosity,
            effective,
            packages_with_manifests: &mut packages_with_manifests,
            pkg_declarations: &mut pkg_declarations,
            multi_lock_warned: &mut multi_lock_warned,
            manifest_coverage: &mut manifest_coverage,
        };

        if parallel_languages {
            let root_for_tasks = root_path.clone();
            let cfg = effective.clone();
            let ctx = resolve_ctx.clone();
            let tasks: Vec<_> = jobs
                .into_iter()
                .map(|job| {
                    let sem = resolution_semaphore.clone();
                    let root = root_for_tasks.clone();
                    let cfg = cfg.clone();
                    let ctx = ctx.clone();
                    async move {
                        run_language_phase(LanguagePhaseArgs {
                            language: job.language,
                            precomputed: job.precomputed,
                            root_path: root.as_path(),
                            finder: job.finder.as_ref(),
                            parser: job.parser.as_ref(),
                            resolver: job.resolver.as_ref(),
                            effective: &cfg,
                            resolve_ctx: &ctx,
                            resolution_semaphore: sem,
                        })
                        .await
                    }
                })
                .collect();
            let joined = futures::future::join_all(tasks).await;
            for item in joined {
                let phase = item?;
                for msg in &phase.deferred_messages {
                    eprintln!("{msg}");
                }
                let _ = apply_language_outcomes(phase.outcomes, &mut sink);
            }
        } else {
            for job in jobs {
                if skip_cve_phase {
                    break;
                }
                let phase = run_language_phase(LanguagePhaseArgs {
                    language: job.language,
                    precomputed: job.precomputed,
                    root_path: root_path.as_path(),
                    finder: job.finder.as_ref(),
                    parser: job.parser.as_ref(),
                    resolver: job.resolver.as_ref(),
                    effective,
                    resolve_ctx: &resolve_ctx,
                    resolution_semaphore: resolution_semaphore.clone(),
                })
                .await?;
                for msg in &phase.deferred_messages {
                    eprintln!("{msg}");
                }
                if apply_language_outcomes(phase.outcomes, &mut sink) {
                    skip_cve_phase = true;
                }
            }
        }
    }

    Ok(finish_resolve_output(
        root_path,
        exclude_dirs,
        packages_with_manifests,
        pkg_declarations,
        manifest_coverage,
        skip_cve_phase,
        discovery_started_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use vlz_manifest_finder::FinderError;
    use vlz_manifest_parser::{
        DependencyGraph, ParserError, ResolveResult, ResolverError,
    };

    #[test]
    fn normalized_exclude_dir_names_trims_and_deduplicates() {
        let input = vec![
            ".git".to_string(),
            " target ".to_string(),
            "".to_string(),
            ".git".to_string(),
        ];
        let got = normalized_exclude_dir_names(&input);
        assert!(got.contains(".git"));
        assert!(got.contains("target"));
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn parallel_languages_enabled_gates() {
        let mut cfg = EffectiveConfig {
            parallel_resolutions: 4,
            ..Default::default()
        };
        assert!(parallel_languages_enabled(&cfg, 2));
        assert!(!parallel_languages_enabled(&cfg, 1));
        cfg.fail_fast = true;
        assert!(!parallel_languages_enabled(&cfg, 2));
        cfg.fail_fast = false;
        cfg.benchmark = true;
        assert!(!parallel_languages_enabled(&cfg, 2));
    }

    #[cfg(feature = "python")]
    #[test]
    fn discover_manifests_one_pass_skips_venv_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let venv_setup = root
            .join(".venv")
            .join("lib")
            .join("python3.13")
            .join("site-packages")
            .join("pkg")
            .join("setup.py");
        std::fs::create_dir_all(venv_setup.parent().unwrap()).unwrap();
        std::fs::write(&venv_setup, "from setuptools import setup\n").unwrap();
        std::fs::write(root.join("requirements.txt"), "y==2.0\n").unwrap();
        let excludes = crate::config::DEFAULT_SCAN_EXCLUDE_DIRS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<HashSet<_>>();
        let got = discover_manifests_one_pass(root, &excludes, &[]).unwrap();
        let manifests = got.0.get("python").cloned().unwrap_or_default();
        assert_eq!(manifests, vec![root.join("requirements.txt")]);
    }

    #[cfg(feature = "python")]
    #[test]
    fn discover_manifests_one_pass_skips_excluded_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git").join("requirements.txt"), "x==1.0\n")
            .unwrap();
        std::fs::write(root.join("requirements.txt"), "y==2.0\n").unwrap();
        let mut excludes = HashSet::new();
        excludes.insert(".git".to_string());
        let got = discover_manifests_one_pass(root, &excludes, &[]).unwrap();
        let manifests = got.0.get("python").cloned().unwrap_or_default();
        assert_eq!(manifests, vec![root.join("requirements.txt")]);
    }

    #[cfg(feature = "python")]
    #[test]
    fn discover_manifests_one_pass_finds_orphan_pylock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let pylock = root.join("pylock.toml");
        std::fs::write(
            &pylock,
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let got = discover_manifests_one_pass(root, &Default::default(), &[])
            .unwrap();
        let manifests = got.0.get("python").cloned().unwrap_or_default();
        assert_eq!(manifests, vec![pylock]);
    }

    #[cfg(feature = "python")]
    #[test]
    fn discover_manifests_one_pass_lock_allowlist_filters_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("poetry.lock"),
            "[[package]]\nname = \"b\"\nversion = \"2.0\"\n",
        )
        .unwrap();
        let got = discover_manifests_one_pass(
            root,
            &Default::default(),
            &["poetry.lock".to_string()],
        )
        .unwrap();
        let manifests = got.0.get("python").cloned().unwrap_or_default();
        assert_eq!(manifests, vec![root.join("poetry.lock")]);
    }

    #[cfg(feature = "python")]
    #[test]
    fn discover_manifests_one_pass_lock_allowlist_missing_listed_lock_errors()
    {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("uv.lock"),
            "version = 1\n\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let err = discover_manifests_one_pass(
            root,
            &Default::default(),
            &["poetry.lock".to_string()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("poetry.lock"));
    }

    struct FakeFinder {
        language: &'static str,
        manifests: Vec<PathBuf>,
        find_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ManifestFinder for FakeFinder {
        fn language_name(&self) -> &str {
            self.language
        }

        async fn find(
            &self,
            _root: &Path,
        ) -> Result<Vec<PathBuf>, FinderError> {
            self.find_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.manifests.clone())
        }
    }

    struct FakeParser;

    #[async_trait]
    impl Parser for FakeParser {
        async fn parse(
            &self,
            manifest: &Path,
        ) -> Result<DependencyGraph, ParserError> {
            Ok(DependencyGraph {
                packages: vec![Package {
                    name: format!("pkg-{}", manifest.display()),
                    version: "1.0".to_string(),
                    ecosystem: None,
                }],
                parsed_dependencies: Vec::new(),
                manifest_path: Some(manifest.to_path_buf()),
            })
        }
    }

    struct FakeResolver {
        language: &'static str,
        barrier: Option<Arc<tokio::sync::Barrier>>,
        current: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        resolve_calls: Arc<AtomicUsize>,
        fail: bool,
        hold: Option<Duration>,
        overlap_flag: Option<Arc<AtomicBool>>,
        in_resolve: Option<Arc<AtomicBool>>,
    }

    #[async_trait]
    impl Resolver for FakeResolver {
        async fn resolve(
            &self,
            graph: &DependencyGraph,
            _ctx: &ResolveContext,
        ) -> Result<ResolveResult, ResolverError> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(ResolverError::Resolve("fake fail".to_string()));
            }
            if let Some(in_resolve) = &self.in_resolve {
                if let Some(overlap) = &self.overlap_flag
                    && in_resolve.load(Ordering::SeqCst)
                {
                    overlap.store(true, Ordering::SeqCst);
                }
                in_resolve.store(true, Ordering::SeqCst);
            }
            let cur = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(cur, Ordering::SeqCst);
            if let Some(barrier) = &self.barrier {
                barrier.wait().await;
            }
            if let Some(hold) = self.hold {
                tokio::time::sleep(hold).await;
            }
            self.current.fetch_sub(1, Ordering::SeqCst);
            if let Some(in_resolve) = &self.in_resolve {
                in_resolve.store(false, Ordering::SeqCst);
            }
            Ok(ResolveResult {
                packages: graph.packages.clone(),
                ..Default::default()
            })
        }

        fn package_manager_available(&self) -> bool {
            true
        }

        fn package_manager_hint(&self) -> &'static str {
            "fake"
        }

        fn language_name(&self) -> &'static str {
            self.language
        }
    }

    fn test_cfg(parallel_resolutions: usize) -> EffectiveConfig {
        EffectiveConfig {
            parallel_resolutions,
            offline: true,
            allow_direct_only_fallback: true,
            ..Default::default()
        }
    }

    #[derive(Clone)]
    struct TwoLangCounters {
        peak: Arc<AtomicUsize>,
        current: Arc<AtomicUsize>,
        a_calls: Arc<AtomicUsize>,
        b_calls: Arc<AtomicUsize>,
        a_find: Arc<AtomicUsize>,
        b_find: Arc<AtomicUsize>,
    }

    impl TwoLangCounters {
        fn new() -> Self {
            Self {
                peak: Arc::new(AtomicUsize::new(0)),
                current: Arc::new(AtomicUsize::new(0)),
                a_calls: Arc::new(AtomicUsize::new(0)),
                b_calls: Arc::new(AtomicUsize::new(0)),
                a_find: Arc::new(AtomicUsize::new(0)),
                b_find: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[derive(Default)]
    struct TwoLangOpts {
        barrier: Option<Arc<tokio::sync::Barrier>>,
        a_fail: bool,
        hold_a: Option<Duration>,
        hold_b: Option<Duration>,
        overlap_flag: Option<Arc<AtomicBool>>,
        in_resolve: Option<Arc<AtomicBool>>,
    }

    async fn run_two_langs(
        cfg: &EffectiveConfig,
        counters: &TwoLangCounters,
        opts: TwoLangOpts,
    ) -> ResolvePackagesOutput {
        let dir = tempfile::tempdir().unwrap();
        let a_mf = dir.path().join("a.manifest");
        let b_mf = dir.path().join("b.manifest");
        std::fs::write(&a_mf, "a").unwrap();
        std::fs::write(&b_mf, "b").unwrap();
        let finders: Vec<Box<dyn ManifestFinder>> = vec![
            Box::new(FakeFinder {
                language: "lang_a",
                manifests: vec![a_mf],
                find_calls: counters.a_find.clone(),
            }),
            Box::new(FakeFinder {
                language: "lang_b",
                manifests: vec![b_mf],
                find_calls: counters.b_find.clone(),
            }),
        ];
        let parsers: Vec<Box<dyn Parser>> =
            vec![Box::new(FakeParser), Box::new(FakeParser)];
        let resolvers: Vec<Box<dyn Resolver>> = vec![
            Box::new(FakeResolver {
                language: "lang_a",
                barrier: opts.barrier.clone(),
                current: counters.current.clone(),
                peak: counters.peak.clone(),
                resolve_calls: counters.a_calls.clone(),
                fail: opts.a_fail,
                hold: opts.hold_a,
                overlap_flag: opts.overlap_flag.clone(),
                in_resolve: opts.in_resolve.clone(),
            }),
            Box::new(FakeResolver {
                language: "lang_b",
                barrier: opts.barrier,
                current: counters.current.clone(),
                peak: counters.peak.clone(),
                resolve_calls: counters.b_calls.clone(),
                fail: false,
                hold: opts.hold_b,
                overlap_flag: opts.overlap_flag,
                in_resolve: opts.in_resolve,
            }),
        ];
        resolve_packages_with_plugins(
            dir.path().to_path_buf(),
            cfg,
            0,
            finders,
            parsers,
            resolvers,
        )
        .await
        .expect("resolve")
    }

    #[tokio::test]
    async fn languages_overlap_when_parallel_enabled() {
        let counters = TwoLangCounters::new();
        let cfg = test_cfg(4);
        let out = run_two_langs(
            &cfg,
            &counters,
            TwoLangOpts {
                barrier: Some(Arc::new(tokio::sync::Barrier::new(2))),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(counters.a_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counters.b_calls.load(Ordering::SeqCst), 1);
        assert_eq!(out.manifest_coverage.len(), 2);
    }

    #[tokio::test]
    async fn shared_semaphore_caps_cross_language_concurrency() {
        let counters = TwoLangCounters::new();
        let cfg = test_cfg(1);
        let _out = run_two_langs(
            &cfg,
            &counters,
            TwoLangOpts {
                hold_a: Some(Duration::from_millis(30)),
                hold_b: Some(Duration::from_millis(30)),
                ..Default::default()
            },
        )
        .await;
        assert!(
            counters.peak.load(Ordering::SeqCst) <= 1,
            "peak concurrent resolutions {}",
            counters.peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn fail_fast_keeps_later_language_unstarted() {
        let counters = TwoLangCounters::new();
        let mut cfg = test_cfg(4);
        cfg.fail_fast = true;
        let out = run_two_langs(
            &cfg,
            &counters,
            TwoLangOpts {
                a_fail: true,
                ..Default::default()
            },
        )
        .await;
        assert!(out.skip_cve_phase);
        assert_eq!(counters.a_find.load(Ordering::SeqCst), 1);
        assert_eq!(counters.b_find.load(Ordering::SeqCst), 0);
        assert_eq!(counters.b_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn registration_order_preserved_despite_completion_order() {
        let counters = TwoLangCounters::new();
        let cfg = test_cfg(4);
        let out = run_two_langs(
            &cfg,
            &counters,
            TwoLangOpts {
                hold_a: Some(Duration::from_millis(40)),
                hold_b: Some(Duration::from_millis(1)),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(out.manifest_coverage.len(), 2);
        assert_eq!(out.manifest_coverage[0].language, "lang_a");
        assert_eq!(out.manifest_coverage[1].language, "lang_b");
    }

    #[tokio::test]
    async fn benchmark_mode_does_not_overlap_language_resolves() {
        let counters = TwoLangCounters::new();
        let overlap = Arc::new(AtomicBool::new(false));
        let in_resolve = Arc::new(AtomicBool::new(false));
        let mut cfg = test_cfg(4);
        cfg.benchmark = true;
        let _out = run_two_langs(
            &cfg,
            &counters,
            TwoLangOpts {
                hold_a: Some(Duration::from_millis(20)),
                hold_b: Some(Duration::from_millis(20)),
                overlap_flag: Some(overlap.clone()),
                in_resolve: Some(in_resolve),
                ..Default::default()
            },
        )
        .await;
        assert!(
            !overlap.load(Ordering::SeqCst),
            "benchmark mode must not overlap language resolves"
        );
    }
}
