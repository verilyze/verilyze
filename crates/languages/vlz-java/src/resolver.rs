// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use vlz_manifest_parser::{
    CachedResolution, DependencyGraph, ResolutionDepth, ResolveContext,
    ResolveResult, Resolver, ResolverError, direct_only_result_from_graph,
    fr022_transitive_error, lock_declarations_from_parsed,
    require_transitive_or_fallback, resolve_declarations_for_packages,
    skip_package_manager_reason,
};

use crate::gradle_cli::{
    gradle_on_path, gradle_pm_hint, run_gradle_dependencies,
    safe_gradle_wrapper,
};
use crate::gradle_root::find_gradle_root;
use crate::lock_names::{list_lock_files_in_dir, select_lock_files};
use crate::maven_cli::{
    maven_pm_hint, mvn_on_path, run_mvn_dependency_list, safe_mvn_wrapper,
};
use crate::parser::parse_gradle_lock_with_declarations;

const PM_TIMEOUT: Duration = Duration::from_secs(120);

/// Manifest kind for per-manifest PM selection (FR-024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaManifestKind {
    Maven,
    Gradle,
    GradleLock,
}

pub fn manifest_kind(path: &Path) -> JavaManifestKind {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if crate::lock_names::is_java_lock_file(name) {
        JavaManifestKind::GradleLock
    } else if name == "pom.xml" {
        JavaManifestKind::Maven
    } else {
        JavaManifestKind::Gradle
    }
}

/// Find Gradle lock files adjacent or in parent dirs up to `scan_root`.
pub fn find_java_lock_files(
    manifest_path: &Path,
    scan_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut dir = match manifest_path.parent() {
        Some(d) => d.to_path_buf(),
        None => return Vec::new(),
    };
    let gradle_root = find_gradle_root(manifest_path, scan_root);
    loop {
        if scan_root.is_some_and(|root| !dir.starts_with(root)) {
            break;
        }
        let candidates = list_lock_files_in_dir(&dir);
        let locks = select_lock_files(&candidates);
        if !locks.is_empty() {
            return locks;
        }
        let _ = gradle_root;
        if scan_root.is_some_and(|root| dir == root) {
            break;
        }
        if !dir.pop() {
            break;
        }
    }
    Vec::new()
}

/// First lock file found for backward-compatible callers.
pub fn find_java_lock_file(
    manifest_path: &Path,
    scan_root: Option<&Path>,
) -> Option<(PathBuf, Vec<String>)> {
    let locks = find_java_lock_files(manifest_path, scan_root);
    if locks.is_empty() {
        return None;
    }
    let names: Vec<String> = locks
        .iter()
        .filter_map(|p| {
            p.file_name().and_then(|n| n.to_str()).map(str::to_string)
        })
        .collect();
    Some((locks[0].clone(), names))
}

fn parse_lock_path(
    lock_path: &Path,
) -> Result<CachedResolution, ResolverError> {
    let content =
        std::fs::read_to_string(lock_path).map_err(ResolverError::Io)?;
    let (packages, parsed) =
        parse_gradle_lock_with_declarations(&content, lock_path)
            .map_err(|e| ResolverError::Resolve(e.to_string()))?;
    Ok(CachedResolution {
        packages,
        package_declarations: lock_declarations_from_parsed(&parsed),
        package_source_paths: HashMap::new(),
    })
}

fn graph_has_unresolved_versions(graph: &DependencyGraph) -> bool {
    graph
        .parsed_dependencies
        .iter()
        .any(|d| d.package.version.is_empty())
        || graph.packages.is_empty()
            && graph.parsed_dependencies.iter().any(|d| {
                !d.package.name.is_empty() && d.package.version.is_empty()
            })
}

fn is_direct_only_manifest(path: &Path) -> bool {
    matches!(
        manifest_kind(path),
        JavaManifestKind::Maven | JavaManifestKind::Gradle
    )
}

/// Resolver: Gradle lock preferred; PM only with SEC-023 opt-in.
#[derive(Debug, Default)]
pub struct JavaResolver {
    lock_cache: Mutex<HashMap<String, CachedResolution>>,
}

impl JavaResolver {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn java_package_manager_available(manifest_path: &Path) -> bool {
    match manifest_kind(manifest_path) {
        JavaManifestKind::Maven => mvn_on_path(),
        JavaManifestKind::Gradle | JavaManifestKind::GradleLock => {
            gradle_on_path()
        }
    }
}

pub fn java_package_manager_hint(manifest_path: &Path) -> &'static str {
    match manifest_kind(manifest_path) {
        JavaManifestKind::Maven => maven_pm_hint(),
        JavaManifestKind::Gradle | JavaManifestKind::GradleLock => {
            gradle_pm_hint()
        }
    }
}

async fn gated_pm_resolve(
    manifest_path: &Path,
    ctx: &ResolveContext,
) -> Result<CachedResolution, ResolverError> {
    let scan_root = ctx
        .scan_root
        .as_deref()
        .unwrap_or_else(|| manifest_path.parent().unwrap_or(Path::new(".")));
    let project_dir = manifest_path.parent().unwrap_or(Path::new("."));

    match manifest_kind(manifest_path) {
        JavaManifestKind::Maven => {
            let mvn_bin = if mvn_on_path() {
                PathBuf::from("mvn")
            } else if let Some(w) = safe_mvn_wrapper(project_dir, scan_root) {
                w
            } else {
                return Err(ResolverError::Resolve(
                    "mvn not on PATH and no safe mvnw wrapper".into(),
                ));
            };
            let packages = tokio::time::timeout(
                PM_TIMEOUT,
                run_mvn_dependency_list(&mvn_bin, project_dir),
            )
            .await
            .map_err(|_| {
                ResolverError::Resolve("mvn dependency:list timed out".into())
            })??;
            Ok(CachedResolution {
                packages,
                package_declarations: HashMap::new(),
                package_source_paths: HashMap::new(),
            })
        }
        JavaManifestKind::Gradle | JavaManifestKind::GradleLock => {
            let gradle_root = find_gradle_root(manifest_path, Some(scan_root));
            let gradle_bin = if gradle_on_path() {
                PathBuf::from("gradle")
            } else if let Some(w) =
                safe_gradle_wrapper(&gradle_root, scan_root)
            {
                w
            } else {
                return Err(ResolverError::Resolve(
                    "gradle not on PATH and no safe gradlew wrapper".into(),
                ));
            };
            let subproject = manifest_path
                .parent()
                .and_then(|p| {
                    p.strip_prefix(&gradle_root)
                        .ok()
                        .filter(|rel| !rel.as_os_str().is_empty())
                })
                .and_then(|rel| rel.to_str().map(String::from));
            let packages = tokio::time::timeout(
                PM_TIMEOUT,
                run_gradle_dependencies(
                    &gradle_bin,
                    &gradle_root,
                    subproject.as_deref(),
                ),
            )
            .await
            .map_err(|_| {
                ResolverError::Resolve("gradle dependencies timed out".into())
            })??;
            Ok(CachedResolution {
                packages,
                package_declarations: HashMap::new(),
                package_source_paths: HashMap::new(),
            })
        }
    }
}

#[async_trait]
impl Resolver for JavaResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        let Some(manifest_path) = graph.manifest_path.as_ref() else {
            return Err(fr022_transitive_error());
        };

        // Lock file as manifest entry point: parsed graph is already transitive.
        if matches!(manifest_kind(manifest_path), JavaManifestKind::GradleLock)
            && !graph.packages.is_empty()
        {
            let package_declarations = resolve_declarations_for_packages(
                &graph.packages,
                graph,
                &lock_declarations_from_parsed(&graph.parsed_dependencies),
            );
            return Ok(ResolveResult {
                packages: graph.packages.clone(),
                depth: ResolutionDepth::Transitive,
                direct_only_reason: None,
                package_declarations,
                resolved_lock_paths: vec![manifest_path.clone()],
                ..Default::default()
            });
        }

        let scan_root = ctx.scan_root.as_deref();
        let lock_paths = find_java_lock_files(manifest_path, scan_root);
        if !lock_paths.is_empty() {
            let mut all_packages = Vec::new();
            let mut all_declarations = HashMap::new();
            let mut seen_packages = HashSet::new();
            for lock_path in &lock_paths {
                let cache_key = lock_path.to_string_lossy().to_string();
                let resolution = {
                    let cache = self.lock_cache.lock().map_err(|e| {
                        ResolverError::Other(format!("lock cache lock: {e}"))
                    })?;
                    cache.get(&cache_key).cloned()
                };
                let resolution = if let Some(c) = resolution {
                    c
                } else {
                    let parsed = parse_lock_path(lock_path)?;
                    if let Ok(mut cache) = self.lock_cache.lock() {
                        cache.insert(cache_key, parsed.clone());
                    }
                    parsed
                };
                for pkg in resolution.packages {
                    let key = format!("{}:{}", pkg.name, pkg.version);
                    if seen_packages.insert(key) {
                        all_packages.push(pkg);
                    }
                }
                all_declarations.extend(resolution.package_declarations);
            }
            if !all_packages.is_empty() {
                let package_declarations = resolve_declarations_for_packages(
                    &all_packages,
                    graph,
                    &all_declarations,
                );
                return Ok(ResolveResult {
                    packages: all_packages,
                    depth: ResolutionDepth::Transitive,
                    direct_only_reason: None,
                    package_declarations,
                    resolved_lock_paths: lock_paths,
                    ..Default::default()
                });
            }
        }

        if let Some(reason) = skip_package_manager_reason(ctx) {
            return Ok(direct_only_result_from_graph(graph, reason));
        }

        // Direct-only manifest (pom, gradle build, catalog) without lock.
        if is_direct_only_manifest(manifest_path)
            && (graph_has_unresolved_versions(graph)
                || !graph.packages.is_empty())
        {
            if !ctx.allow_dependency_code_execution {
                return require_transitive_or_fallback(graph, ctx, None);
            }
            match gated_pm_resolve(manifest_path, ctx).await {
                Ok(resolution) if !resolution.packages.is_empty() => {
                    let package_declarations =
                        resolve_declarations_for_packages(
                            &resolution.packages,
                            graph,
                            &resolution.package_declarations,
                        );
                    return Ok(ResolveResult {
                        packages: resolution.packages,
                        depth: ResolutionDepth::Transitive,
                        direct_only_reason: None,
                        package_declarations,
                        ..Default::default()
                    });
                }
                Ok(_) | Err(_) => {
                    return require_transitive_or_fallback(graph, ctx, None);
                }
            }
        }

        if graph.packages.is_empty() && graph.parsed_dependencies.is_empty() {
            return Ok(ResolveResult {
                packages: Vec::new(),
                depth: ResolutionDepth::Transitive,
                ..Default::default()
            });
        }

        require_transitive_or_fallback(graph, ctx, None)
    }

    fn package_manager_available(&self) -> bool {
        mvn_on_path() || gradle_on_path()
    }

    fn package_manager_hint(&self) -> &'static str {
        "Install Maven (mvn) and/or Gradle for Java resolution."
    }

    fn package_manager_available_for_manifest(
        &self,
        manifest_path: &Path,
    ) -> bool {
        java_package_manager_available(manifest_path)
    }

    fn package_manager_hint_for_manifest(
        &self,
        manifest_path: &Path,
    ) -> &'static str {
        java_package_manager_hint(manifest_path)
    }

    fn manifest_needs_package_manager(
        &self,
        manifest_path: &Path,
        ctx: &ResolveContext,
    ) -> bool {
        if matches!(manifest_kind(manifest_path), JavaManifestKind::GradleLock)
        {
            return false;
        }
        find_java_lock_files(manifest_path, ctx.scan_root.as_deref())
            .is_empty()
            && is_direct_only_manifest(manifest_path)
    }

    fn language_name(&self) -> &'static str {
        "java"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::Package;

    #[test]
    fn find_lock_files_in_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sub = root.join("module");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("pom.xml"), "<project/>").unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.root:lib:1.0=compileClasspath\n",
        )
        .unwrap();
        let locks = find_java_lock_files(&sub.join("pom.xml"), Some(root));
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].file_name().unwrap(), "gradle.lockfile");
    }

    #[test]
    fn manifest_needs_pm_false_when_lock_present() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("build.gradle"), "plugins {}").unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.a:b:1.0=compileClasspath\n",
        )
        .unwrap();
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        assert!(
            !resolver.manifest_needs_package_manager(
                &root.join("build.gradle"),
                &ctx,
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn gated_pm_resolve_maven_with_fake_mvnw() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("pom.xml"),
            r#"<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"#,
        )
        .unwrap();
        std::fs::write(
            root.join("mvnw"),
            "#!/bin/sh\n\
             echo 'com.pm:resolved:jar:9.9:compile'\n",
        )
        .unwrap();
        std::fs::set_permissions(
            root.join("mvnw"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "g:a".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(root.join("pom.xml")),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            allow_dependency_code_execution: true,
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        temp_env::with_var("PATH", Some(""), || {
            let result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(resolver.resolve(&graph, &ctx))
                .unwrap();
            assert!(
                result.packages.iter().any(|p| p.name == "com.pm:resolved")
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn gated_pm_resolve_gradle_with_fake_gradlew() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("settings.gradle"), "rootProject.name='p'\n")
            .unwrap();
        std::fs::write(root.join("build.gradle"), "plugins {}").unwrap();
        std::fs::write(
            root.join("gradlew"),
            "#!/bin/sh\n\
             echo '+--- com.pm:gradle:9.9'\n",
        )
        .unwrap();
        std::fs::set_permissions(
            root.join("gradlew"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "com.local:app".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(root.join("build.gradle")),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            allow_dependency_code_execution: true,
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        temp_env::with_var("PATH", Some(""), || {
            let result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(resolver.resolve(&graph, &ctx))
                .unwrap();
            assert!(result.packages.iter().any(|p| p.name == "com.pm:gradle"));
        });
    }

    #[test]
    fn java_pm_available_and_hint_per_manifest_kind() {
        assert!(
            java_package_manager_hint(Path::new("pom.xml")).contains("Maven")
        );
        assert!(
            java_package_manager_hint(Path::new("build.gradle"))
                .contains("Gradle")
        );
    }

    #[tokio::test]
    async fn empty_graph_returns_empty_packages() {
        let resolver = JavaResolver::new();
        let graph = DependencyGraph {
            packages: Vec::new(),
            parsed_dependencies: Vec::new(),
            manifest_path: Some(PathBuf::from("pom.xml")),
        };
        let result = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert!(result.packages.is_empty());
    }

    #[tokio::test]
    async fn missing_manifest_path_fails_fr022() {
        let resolver = JavaResolver::new();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "g:a".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: None,
        };
        assert!(
            resolver
                .resolve(&graph, &ResolveContext::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn gradle_lock_manifest_is_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("gradle.lockfile");
        std::fs::write(&lock, "com.a:b:1.0=compileClasspath\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "com.a:b".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(lock.clone()),
        };
        let resolver = JavaResolver::new();
        let result = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.resolved_lock_paths, vec![lock]);
    }

    #[tokio::test]
    async fn offline_returns_direct_only_for_lockless_pom() {
        let dir = tempfile::tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        std::fs::write(
            &pom,
            r#"<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "g:a".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(pom),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert!(result.direct_only_reason.is_some());
    }

    #[tokio::test]
    async fn offline_with_gradle_lock_stays_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("build.gradle"), "dependencies {}").unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.a:b:1.0=compileClasspath\n",
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "com.a:b".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(root.join("build.gradle")),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert_eq!(result.direct_only_reason, None);
        assert!(result.packages.iter().any(|p| p.name == "com.a:b"));
    }

    #[tokio::test]
    async fn benchmark_with_gradle_lock_stays_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("build.gradle"), "dependencies {}").unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.a:b:1.0=compileClasspath\n",
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "com.a:b".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(root.join("build.gradle")),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: true,
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert_eq!(result.direct_only_reason, None);
    }

    #[tokio::test]
    async fn offline_empty_gradle_lock_falls_through_direct_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("build.gradle"), "dependencies {}").unwrap();
        std::fs::write(root.join("gradle.lockfile"), "empty=\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "com.a:b".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(root.join("build.gradle")),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(
            result.direct_only_reason,
            Some(vlz_manifest_parser::DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[test]
    fn resolver_trait_metadata() {
        let resolver = JavaResolver::new();
        assert_eq!(resolver.language_name(), "java");
        assert_eq!(
            resolver.package_manager_hint_for_manifest(Path::new("pom.xml")),
            java_package_manager_hint(Path::new("pom.xml")),
        );
    }

    #[test]
    fn find_lock_adjacent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("build.gradle"), "dependencies {}").unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.a:b:1.0=compileClasspath\n",
        )
        .unwrap();
        let found =
            find_java_lock_file(&root.join("build.gradle"), Some(root));
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn merges_packages_from_multiple_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("build.gradle"), "dependencies {}").unwrap();
        std::fs::write(
            root.join("gradle.lockfile"),
            "com.a:b:1.0=compileClasspath\n",
        )
        .unwrap();
        std::fs::write(
            root.join("buildscript-gradle.lockfile"),
            "com.c:d:2.0=compileClasspath\n",
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "com.a:b".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(root.join("build.gradle")),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext {
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.resolved_lock_paths.len(), 2);
        assert!(result.packages.iter().any(|p| p.name == "com.a:b"));
        assert!(result.packages.iter().any(|p| p.name == "com.c:d"));
    }

    #[tokio::test]
    async fn lockless_pom_exits_via_require_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        std::fs::write(
            &pom,
            r#"<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "g:a".into(),
                version: "1.0".into(),
                ecosystem: Some("Maven".into()),
            }],
            parsed_dependencies: vec![],
            manifest_path: Some(pom),
        };
        let resolver = JavaResolver::new();
        let ctx = ResolveContext::default();
        let err = resolver.resolve(&graph, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("transitive"));
    }
}
