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
use vlz_reachability::PackageContext;
use vlz_report::ManifestCoverageEntry;

use crate::cache_warm::deduplicate_packages;
use crate::config::EffectiveConfig;

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
        effective.parallel_resolutions
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
    let mut direct_only_warned: HashSet<(PathBuf, &'static str)> =
        HashSet::new();
    let mut multi_lock_warned: HashSet<PathBuf> = HashSet::new();
    let mut manifest_coverage: Vec<ManifestCoverageEntry> = Vec::new();
    let mut skip_cve_phase = false;
    let resolve_ctx = vlz_manifest_parser::ResolveContext {
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

    for i in 0..n {
        if skip_cve_phase {
            break;
        }
        let language = finders[i].language_name().to_string();
        let language_discovery_started_at = Instant::now();
        let mut manifests = if can_use_shared_discovery {
            manifests_by_language.remove(&language).unwrap_or_default()
        } else if language == "python" {
            #[cfg(feature = "python")]
            {
                if effective.language_regexes.is_empty() {
                    vlz_python::PythonManifestFinder::new()
                        .with_lock_file_allowlist(
                            effective.python_lock_files.clone(),
                        )
                        .find(&root_path)
                        .await
                        .context("Failed during manifest discovery")?
                } else {
                    finders[i]
                        .find(&root_path)
                        .await
                        .context("Failed during manifest discovery")?
                }
            }
            #[cfg(not(feature = "python"))]
            Vec::new()
        } else {
            finders[i]
                .find(&root_path)
                .await
                .context("Failed during manifest discovery")?
        };
        manifests.sort();
        #[cfg(feature = "python")]
        if !can_use_shared_discovery && language == "python" {
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
                eprintln!(
                    "{}",
                    vlz_manifest_parser::format_multi_lock_warning(
                        &dir.display().to_string(),
                        &lock_names,
                    )
                );
            }
        }
        let language_discovery_ms =
            language_discovery_started_at.elapsed().as_millis();
        info!(
            "Found {} manifest(s) for {} in {} ms",
            manifests.len(),
            language,
            language_discovery_ms
        );
        let parser = &parsers[i];
        let resolver = &resolvers[i];
        let ctx = resolve_ctx.clone();
        let resolution_semaphore =
            Arc::new(Semaphore::new(effective_resolution_parallel));
        let manifest_count = manifests.len();
        if manifest_count > 1 {
            eprintln!("Resolving {manifest_count} {language} manifest(s)...");
        }
        let tasks: Vec<_> = manifests
            .into_iter()
            .map(|mf| {
                let language = language.clone();
                let ctx = ctx.clone();
                let resolution_sem = resolution_semaphore.clone();
                async move {
                    match parser.parse(&mf).await {
                        Ok(graph) => {
                            let _permit = resolution_sem.acquire().await;
                            match resolver.resolve(&graph, &ctx).await {
                                Ok(resolved) => {
                                    crate::scan::ManifestTaskOutcome::Success {
                                        resolved,
                                        manifest_path: mf,
                                        language,
                                    }
                                }
                                Err(error) => {
                                    crate::scan::ManifestTaskOutcome::ResolveFailed {
                                        manifest_path: mf,
                                        language,
                                        error,
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            crate::scan::ManifestTaskOutcome::ParseFailed {
                                manifest_path: mf,
                                language,
                                error,
                            }
                        }
                    }
                }
            })
            .collect();
        let mut outcomes = futures::future::join_all(tasks).await;
        outcomes.sort_by(|a, b| a.manifest_path().cmp(b.manifest_path()));
        for outcome in outcomes {
            match outcome {
                crate::scan::ManifestTaskOutcome::Success {
                    resolved,
                    manifest_path,
                    language,
                } => {
                    manifest_coverage.push(
                        crate::scan::coverage_entry_success(
                            manifest_path.clone(),
                            language.clone(),
                            &resolved,
                        ),
                    );
                    if resolved.depth
                        == vlz_manifest_parser::ResolutionDepth::DirectOnly
                        && let Some(reason) = resolved.direct_only_reason
                        && direct_only_warned
                            .insert((manifest_path.clone(), reason))
                    {
                        eprintln!(
                            "{}",
                            vlz_manifest_parser::format_direct_only_warning(
                                &manifest_path.display().to_string(),
                                reason,
                            )
                        );
                    }
                    if resolved.resolved_lock_paths.len() > 1
                        && let Some(dir) = manifest_path.parent()
                        && multi_lock_warned.insert(dir.to_path_buf())
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
                        &mut pkg_declarations,
                        resolved.package_declarations,
                    );
                    for pkg in resolved.packages {
                        if let Some(sources) =
                            resolved.package_source_paths.get(&pkg)
                        {
                            for path in sources {
                                packages_with_manifests.push((
                                    pkg.clone(),
                                    path.clone(),
                                    language.clone(),
                                ));
                            }
                        } else {
                            packages_with_manifests.push((
                                pkg,
                                manifest_path.clone(),
                                language.clone(),
                            ));
                        }
                    }
                }
                crate::scan::ManifestTaskOutcome::ParseFailed {
                    manifest_path,
                    language,
                    error,
                } => {
                    manifest_coverage.push(
                        crate::scan::coverage_entry_parse_failure(
                            manifest_path.clone(),
                            language,
                            &error,
                        ),
                    );
                    crate::scan::log_manifest_failure(
                        &manifest_path,
                        &error,
                        verbosity,
                        Some(root_path.as_path()),
                    );
                    if effective.fail_fast {
                        skip_cve_phase = true;
                        break;
                    }
                }
                crate::scan::ManifestTaskOutcome::ResolveFailed {
                    manifest_path,
                    language,
                    error,
                } => {
                    manifest_coverage.push(
                        crate::scan::coverage_entry_resolution_failure(
                            manifest_path.clone(),
                            language,
                            &error,
                        ),
                    );
                    crate::scan::log_manifest_failure(
                        &manifest_path,
                        &error,
                        verbosity,
                        Some(root_path.as_path()),
                    );
                    if effective.fail_fast {
                        skip_cve_phase = true;
                        break;
                    }
                }
            }
        }
    }
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

    Ok(ResolvePackagesOutput {
        root_path,
        exclude_dirs,
        packages_with_manifests,
        pkg_declarations,
        pkg_contexts,
        packages_to_check,
        manifest_coverage,
        skip_cve_phase,
        package_manager_missing: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
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
            "[[packages]]\nname = \"a\"\nversion = \"1.0\"\n",
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
}
