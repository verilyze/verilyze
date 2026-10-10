// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use vlz_manifest_parser::{
    CachedResolution, DependencyGraph, ResolutionDepth, ResolveContext,
    ResolveResult, Resolver, ResolverError, direct_only_result_from_graph,
    fr022_transitive_error, lock_declarations_from_parsed,
    require_transitive_or_fallback, resolve_declarations_for_packages,
    skip_package_manager_reason,
};

use crate::lock_names::DART_LOCK_FILE_NAMES;
use crate::parser::{
    DART_LOCK_MAX_BYTES, parse_pubspec_lock_with_declarations,
};

/// Find `pubspec.lock` next to the manifest or in parent directories up to
/// the scan root (Dart workspaces keep one root lock for all members).
pub fn find_dart_lock_file(
    manifest_path: &Path,
    scan_root: Option<&Path>,
) -> Option<PathBuf> {
    let mut dir = manifest_path.parent()?.to_path_buf();
    loop {
        if scan_root.is_some_and(|root| !dir.starts_with(root)) {
            return None;
        }
        for lock_name in DART_LOCK_FILE_NAMES {
            let candidate = dir.join(lock_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        if scan_root.is_some_and(|root| dir == root) || !dir.pop() {
            return None;
        }
    }
}

fn parse_lock_path(path: &Path) -> Result<CachedResolution, ResolverError> {
    let metadata = std::fs::metadata(path).map_err(ResolverError::Io)?;
    if metadata.len() > DART_LOCK_MAX_BYTES {
        return Err(ResolverError::Resolve(format!(
            "pubspec.lock exceeds {DART_LOCK_MAX_BYTES} byte limit"
        )));
    }
    let content = std::fs::read_to_string(path).map_err(ResolverError::Io)?;
    let (packages, parsed) =
        parse_pubspec_lock_with_declarations(&content, path)
            .map_err(|error| ResolverError::Resolve(error.to_string()))?;
    Ok(CachedResolution {
        packages,
        package_declarations: lock_declarations_from_parsed(&parsed),
        package_source_paths: HashMap::new(),
    })
}

/// Hint text (FR-024); Dart resolution never invokes a package manager, so
/// this only documents how to produce the lock.
const DART_LOCK_HINT: &str = "Commit pubspec.lock (run `dart pub get` or `flutter pub get` in a trusted checkout).";

/// Resolver: committed `pubspec.lock` only (SEC-023); no `dart` / `flutter`
/// binary is ever executed by the scanner.
#[derive(Debug, Default)]
pub struct DartResolver {
    lock_cache: Mutex<HashMap<PathBuf, CachedResolution>>,
}

impl DartResolver {
    /// Create a new Dart resolver.
    pub fn new() -> Self {
        Self::default()
    }

    fn cached_or_parse(
        &self,
        lock_path: &Path,
    ) -> Result<Option<CachedResolution>, ResolverError> {
        let cached = self
            .lock_cache
            .lock()
            .map_err(|error| {
                ResolverError::Other(format!("lock cache lock: {error}"))
            })?
            .get(lock_path)
            .cloned();
        if cached.is_some() {
            return Ok(cached);
        }
        let parsed = parse_lock_path(lock_path)?;
        if parsed.packages.is_empty() {
            return Ok(None);
        }
        if let Ok(mut cache) = self.lock_cache.lock() {
            cache.insert(lock_path.to_path_buf(), parsed.clone());
        }
        Ok(Some(parsed))
    }
}

#[async_trait]
impl Resolver for DartResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        let Some(manifest) = graph.manifest_path.as_deref() else {
            return Err(fr022_transitive_error());
        };
        if let Some(lock_path) =
            find_dart_lock_file(manifest, ctx.scan_root.as_deref())
        {
            if let Some(resolution) = self.cached_or_parse(&lock_path)? {
                return Ok(ResolveResult {
                    package_declarations: resolve_declarations_for_packages(
                        &resolution.packages,
                        graph,
                        &resolution.package_declarations,
                    ),
                    packages: resolution.packages,
                    depth: ResolutionDepth::Transitive,
                    resolved_lock_paths: vec![lock_path],
                    ..Default::default()
                });
            }
            if graph.packages.is_empty() {
                return Ok(ResolveResult::default());
            }
        }
        if let Some(reason) = skip_package_manager_reason(ctx) {
            return Ok(direct_only_result_from_graph(graph, reason));
        }
        require_transitive_or_fallback(graph, ctx, None)
    }

    fn package_manager_available(&self) -> bool {
        true
    }

    fn package_manager_hint(&self) -> &'static str {
        DART_LOCK_HINT
    }

    fn manifest_needs_package_manager(
        &self,
        _manifest_path: &Path,
        _ctx: &ResolveContext,
    ) -> bool {
        false
    }

    fn language_name(&self) -> &'static str {
        "dart"
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::{PUB_ECOSYSTEM, Package};
    use vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE;

    const LOCK: &str = "packages:\n  http:\n    description:\n      name: http\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.2.2\"\n  async:\n    description:\n      name: async\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"2.11.0\"\n";
    const EMPTY_LOCK: &str = "packages: {}\n";

    fn graph_for(manifest: std::path::PathBuf) -> DependencyGraph {
        DependencyGraph {
            packages: vec![Package {
                name: "http".into(),
                version: "^1.0.0".into(),
                ecosystem: Some(PUB_ECOSYSTEM.into()),
                ..Default::default()
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(manifest),
        }
    }

    fn ctx_for(root: &Path) -> ResolveContext {
        ResolveContext {
            scan_root: Some(root.to_path_buf()),
            ..Default::default()
        }
    }

    #[test]
    fn parent_walk_finds_lock_for_workspace_member() {
        let dir = tempfile::tempdir().unwrap();
        let member = dir.path().join("packages").join("app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(dir.path().join("pubspec.lock"), LOCK).unwrap();
        std::fs::write(member.join("pubspec.yaml"), "name: app\n").unwrap();
        let found = find_dart_lock_file(
            &member.join("pubspec.yaml"),
            Some(dir.path()),
        )
        .unwrap();
        assert_eq!(found, dir.path().join("pubspec.lock"));
    }

    #[test]
    fn parent_walk_stops_at_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let scan = dir.path().join("scan");
        let nested = scan.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("pubspec.lock"), LOCK).unwrap();
        std::fs::write(nested.join("pubspec.yaml"), "name: n\n").unwrap();
        assert!(
            find_dart_lock_file(&nested.join("pubspec.yaml"), Some(&scan))
                .is_none()
        );
    }

    #[tokio::test]
    async fn usable_lock_is_transitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pubspec.lock"), LOCK).unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "name: app\n").unwrap();
        let result = DartResolver::new()
            .resolve(&graph_for(manifest), &ctx_for(dir.path()))
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert!(result.packages.iter().any(|p| p.name == "async"));
        assert_eq!(result.resolved_lock_paths.len(), 1);
    }

    #[tokio::test]
    async fn offline_with_lock_stays_transitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pubspec.lock"), LOCK).unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "name: app\n").unwrap();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..ctx_for(dir.path())
        };
        let result = DartResolver::new()
            .resolve(&graph_for(manifest), &ctx)
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert_eq!(result.direct_only_reason, None);
    }

    #[tokio::test]
    async fn orphan_lock_entry_resolves_itself() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("pubspec.lock");
        std::fs::write(&lock, LOCK).unwrap();
        let graph = DependencyGraph {
            manifest_path: Some(lock),
            ..Default::default()
        };
        let result = DartResolver::new()
            .resolve(&graph, &ctx_for(dir.path()))
            .await
            .unwrap();
        assert_eq!(result.packages.len(), 2);
    }

    #[tokio::test]
    async fn lockless_is_fr022_even_with_exec_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "dependencies:\n  http: ^1.0.0\n").unwrap();
        for allow in [false, true] {
            let ctx = ResolveContext {
                allow_dependency_code_execution: allow,
                ..ctx_for(dir.path())
            };
            let err = DartResolver::new()
                .resolve(&graph_for(manifest.clone()), &ctx)
                .await
                .unwrap_err();
            assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
        }
    }

    #[tokio::test]
    async fn empty_lock_with_declared_deps_is_not_transitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pubspec.lock"), EMPTY_LOCK).unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "dependencies:\n  http: ^1.0.0\n").unwrap();
        let err = DartResolver::new()
            .resolve(&graph_for(manifest), &ctx_for(dir.path()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }

    #[tokio::test]
    async fn empty_lock_with_empty_manifest_is_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pubspec.lock"), EMPTY_LOCK).unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "name: app\n").unwrap();
        let graph = DependencyGraph {
            manifest_path: Some(manifest),
            ..Default::default()
        };
        let result = DartResolver::new()
            .resolve(&graph, &ctx_for(dir.path()))
            .await
            .unwrap();
        assert!(result.packages.is_empty());
        assert_eq!(result.depth, ResolutionDepth::Transitive);
    }

    #[tokio::test]
    async fn offline_lockless_is_direct_only() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "dependencies:\n  http: ^1.0.0\n").unwrap();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..ctx_for(dir.path())
        };
        let result = DartResolver::new()
            .resolve(&graph_for(manifest), &ctx)
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert!(result.direct_only_reason.is_some());
    }

    #[tokio::test]
    async fn allow_direct_only_fallback_without_lock() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "dependencies:\n  http: ^1.0.0\n").unwrap();
        let ctx = ResolveContext {
            allow_direct_only_fallback: true,
            ..ctx_for(dir.path())
        };
        let result = DartResolver::new()
            .resolve(&graph_for(manifest), &ctx)
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    }

    #[tokio::test]
    async fn missing_manifest_path_is_fr022() {
        let err = DartResolver::new()
            .resolve(&DependencyGraph::default(), &ResolveContext::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains(FR_022_TRANSITIVE_ERROR_MESSAGE));
    }

    #[tokio::test]
    async fn oversized_lock_is_resolve_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pubspec.lock"),
            vec![b'x'; DART_LOCK_MAX_BYTES as usize + 1],
        )
        .unwrap();
        let manifest = dir.path().join("pubspec.yaml");
        std::fs::write(&manifest, "name: app\n").unwrap();
        assert!(
            DartResolver::new()
                .resolve(&graph_for(manifest), &ctx_for(dir.path()))
                .await
                .is_err()
        );
    }

    #[test]
    fn package_manager_is_never_required() {
        let resolver = DartResolver::new();
        let ctx = ResolveContext::default();
        assert!(resolver.package_manager_available());
        assert!(!resolver.manifest_needs_package_manager(
            Path::new("/x/pubspec.yaml"),
            &ctx
        ));
        assert!(!resolver.package_manager_hint().is_empty());
        assert_eq!(resolver.language_name(), "dart");
    }
}
