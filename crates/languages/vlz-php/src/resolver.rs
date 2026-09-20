// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use vlz_manifest_parser::{
    CachedResolution, DependencyGraph, ResolutionDepth, ResolveContext,
    ResolveResult, Resolver, ResolverError, direct_only_result_from_graph,
    fr022_transitive_error, lock_declarations_from_parsed,
    require_transitive_or_fallback, resolve_declarations_for_packages,
    skip_package_manager_reason,
};

use crate::lock_names::PHP_LOCK_FILE_NAMES;
use crate::parser::{
    PHP_LOCK_MAX_BYTES, parse_composer_lock_with_declarations,
};

const COMPOSER_TIMEOUT: Duration = Duration::from_secs(120);

/// Find `composer.lock` next to the manifest or in parent directories up to
/// the scan root.
pub fn find_php_lock_file(
    manifest_path: &Path,
    scan_root: Option<&Path>,
) -> Option<PathBuf> {
    let mut dir = manifest_path.parent()?.to_path_buf();
    loop {
        if scan_root.is_some_and(|root| !dir.starts_with(root)) {
            return None;
        }
        for lock_name in PHP_LOCK_FILE_NAMES {
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
    if metadata.len() > PHP_LOCK_MAX_BYTES {
        return Err(ResolverError::Resolve(format!(
            "composer.lock exceeds {} byte limit",
            PHP_LOCK_MAX_BYTES
        )));
    }
    let content = std::fs::read_to_string(path).map_err(ResolverError::Io)?;
    let (packages, parsed) =
        parse_composer_lock_with_declarations(&content, path)
            .map_err(|error| ResolverError::Resolve(error.to_string()))?;
    Ok(CachedResolution {
        packages,
        package_declarations: lock_declarations_from_parsed(&parsed),
        package_source_paths: HashMap::new(),
    })
}

/// True when `composer` appears on PATH.
pub fn php_package_manager_available() -> bool {
    vlz_manifest_parser::package_manager_command_ok("composer", &["--version"])
}

/// OS-specific hint when Composer is not found (FR-024).
pub fn php_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: apt-get install composer (Debian/Ubuntu) or dnf install composer (Fedora/RHEL), or https://getcomposer.org/.";
    #[cfg(target_os = "macos")]
    return "Install via: brew install composer, or https://getcomposer.org/.";
    #[cfg(target_os = "windows")]
    return "Install Composer from https://getcomposer.org/ and ensure composer is on PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install PHP Composer for your platform (https://getcomposer.org/).";
}

async fn ephemeral_composer_lock(
    manifest_path: &Path,
) -> Result<CachedResolution, ResolverError> {
    if !php_package_manager_available() {
        return Err(ResolverError::Resolve(
            "composer is not available on PATH".into(),
        ));
    }
    let temp = tempfile::Builder::new()
        .prefix("vlz-php-")
        .tempdir()
        .map_err(ResolverError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            temp.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(ResolverError::Io)?;
    }

    let destination = temp.path().join("composer.json");
    std::fs::copy(manifest_path, &destination).map_err(ResolverError::Io)?;

    let mut command = tokio::process::Command::new("composer");
    command
        .args([
            "update",
            "--no-install",
            "--no-scripts",
            "--no-plugins",
            "--no-interaction",
        ])
        .current_dir(temp.path())
        .kill_on_drop(true);
    let output = tokio::time::timeout(COMPOSER_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            ResolverError::Resolve(format!(
                "composer update timed out after {}s",
                COMPOSER_TIMEOUT.as_secs()
            ))
        })?
        .map_err(ResolverError::Io)?;
    if !output.status.success() {
        return Err(ResolverError::Resolve(format!(
            "composer update failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let lock = temp.path().join("composer.lock");
    if !lock.is_file() {
        return Err(ResolverError::Resolve(
            "composer update did not produce composer.lock".into(),
        ));
    }
    parse_lock_path(&lock)
}

/// Resolver: adjacent/parent lock preferred; Composer only with SEC-023 opt-in.
#[derive(Debug, Default)]
pub struct PhpResolver {
    lock_cache: Mutex<HashMap<PathBuf, CachedResolution>>,
}

impl PhpResolver {
    /// Create a new PHP Composer resolver.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Resolver for PhpResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        if let Some(manifest) = graph.manifest_path.as_deref()
            && let Some(lock_path) =
                find_php_lock_file(manifest, ctx.scan_root.as_deref())
        {
            let cached = self
                .lock_cache
                .lock()
                .map_err(|error| {
                    ResolverError::Other(format!("lock cache lock: {error}"))
                })?
                .get(&lock_path)
                .filter(|cached| !cached.packages.is_empty())
                .cloned();
            let resolution = if let Some(cached) = cached {
                Some(cached)
            } else {
                let parsed = parse_lock_path(&lock_path)?;
                if parsed.packages.is_empty() {
                    None
                } else {
                    if let Ok(mut cache) = self.lock_cache.lock() {
                        cache.insert(lock_path.clone(), parsed.clone());
                    }
                    Some(parsed)
                }
            };
            if let Some(resolution) = resolution {
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
            // Empty lock: fall through to offline/FR-022/gated composer.
        }

        if let Some(reason) = skip_package_manager_reason(ctx) {
            return Ok(direct_only_result_from_graph(graph, reason));
        }
        let Some(manifest) = graph.manifest_path.as_deref() else {
            return Err(fr022_transitive_error());
        };
        if !ctx.allow_dependency_code_execution {
            return require_transitive_or_fallback(graph, ctx, None);
        }
        match ephemeral_composer_lock(manifest).await {
            Ok(resolution) => Ok(ResolveResult {
                package_declarations: resolve_declarations_for_packages(
                    &resolution.packages,
                    graph,
                    &resolution.package_declarations,
                ),
                packages: resolution.packages,
                depth: ResolutionDepth::Transitive,
                ..Default::default()
            }),
            Err(error) => {
                require_transitive_or_fallback(graph, ctx, Some(error))
            }
        }
    }

    fn package_manager_available(&self) -> bool {
        php_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        php_package_manager_hint()
    }

    fn manifest_needs_package_manager(
        &self,
        manifest_path: &Path,
        ctx: &ResolveContext,
    ) -> bool {
        find_php_lock_file(manifest_path, ctx.scan_root.as_deref()).is_none()
    }

    fn language_name(&self) -> &'static str {
        "php"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::{PACKAGIST_ECOSYSTEM, Package};

    fn sample_lock() -> &'static str {
        r#"{
  "packages": [
    {
      "name": "symfony/http-foundation",
      "version": "6.4.0",
      "dist": { "type": "zip", "url": "https://example.test/a.zip" }
    }
  ],
  "packages-dev": []
}"#
    }

    #[test]
    fn parent_walk_stops_at_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let scan = dir.path().join("scan");
        let nested = scan.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("composer.lock"), "{}").unwrap();
        std::fs::write(nested.join("composer.json"), "{}").unwrap();
        assert!(
            find_php_lock_file(&nested.join("composer.json"), Some(&scan))
                .is_none()
        );
    }

    #[test]
    fn parent_walk_finds_lock() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("apps").join("web");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("composer.lock"), sample_lock())
            .unwrap();
        std::fs::write(nested.join("composer.json"), "{}").unwrap();
        let found = find_php_lock_file(
            &nested.join("composer.json"),
            Some(dir.path()),
        )
        .unwrap();
        assert!(found.ends_with("composer.lock"));
    }

    #[tokio::test]
    async fn resolve_from_lock_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("composer.json"),
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        std::fs::write(tmp.join("composer.lock"), sample_lock()).unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("composer.json")),
        };
        let result = PhpResolver::new()
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert!(result.packages.iter().any(|p| {
            p.name == "symfony/http-foundation" && p.version == "6.4.0"
        }));
    }

    #[tokio::test]
    async fn lockless_without_exec_is_fr022() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("composer.json");
        std::fs::write(
            &manifest,
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(manifest),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = PhpResolver::new().resolve(&graph, &ctx).await.unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            )
        );
    }

    #[tokio::test]
    async fn empty_lock_falls_through_to_fr022() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("composer.json");
        std::fs::write(
            &manifest,
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("composer.lock"),
            r#"{"packages":[],"packages-dev":[]}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(manifest),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = PhpResolver::new().resolve(&graph, &ctx).await.unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            )
        );
    }

    #[tokio::test]
    async fn offline_with_lock_stays_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("composer.json"),
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        std::fs::write(tmp.join("composer.lock"), sample_lock()).unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("composer.json")),
        };
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..Default::default()
        };
        let result = PhpResolver::new().resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert_eq!(result.direct_only_reason, None);
    }

    #[tokio::test]
    async fn offline_lockless_returns_direct_only() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("composer.json");
        std::fs::write(
            &manifest,
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(manifest),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            skip_pip_resolution: true,
            ..Default::default()
        };
        let result = PhpResolver::new().resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert!(result.direct_only_reason.is_some());
    }

    #[tokio::test]
    async fn allow_direct_only_fallback_without_exec() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("composer.json");
        std::fs::write(
            &manifest,
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(manifest),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            allow_direct_only_fallback: true,
            ..Default::default()
        };
        let result = PhpResolver::new().resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    }

    #[test]
    fn manifest_needs_package_manager_tracks_lock() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("composer.json");
        std::fs::write(&manifest, "{}").unwrap();
        let resolver = PhpResolver::new();
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert!(resolver.manifest_needs_package_manager(&manifest, &ctx));
        std::fs::write(dir.path().join("composer.lock"), "{}").unwrap();
        assert!(!resolver.manifest_needs_package_manager(&manifest, &ctx));
    }

    #[test]
    fn resolver_metadata_is_stable() {
        let resolver = PhpResolver::new();
        assert_eq!(resolver.language_name(), "php");
        assert!(!resolver.package_manager_hint().is_empty());
        let _ = resolver.package_manager_available();
    }

    #[tokio::test]
    async fn resolve_missing_manifest_path_is_fr022() {
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "a/b".into(),
                version: "1.0.0".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: None,
        };
        let err = PhpResolver::new()
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            )
        );
    }

    #[tokio::test]
    async fn second_resolve_hits_lock_cache() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("composer.json"),
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        std::fs::write(tmp.join("composer.lock"), sample_lock()).unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("composer.json")),
        };
        let resolver = PhpResolver::new();
        let first = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        let second = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(first.depth, ResolutionDepth::Transitive);
        assert_eq!(second.depth, ResolutionDepth::Transitive);
    }

    #[cfg(unix)]
    static FAKE_COMPOSER_PATH_LOCK: std::sync::Mutex<()> =
        std::sync::Mutex::new(());

    #[cfg(unix)]
    fn write_fake_composer(bin_dir: &Path, script: &str) {
        use std::os::unix::fs::PermissionsExt;
        let bin_path = bin_dir.join("composer");
        std::fs::write(&bin_path, script).unwrap();
        let mut perms = std::fs::metadata(&bin_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin_path, perms).unwrap();
    }

    #[cfg(unix)]
    #[allow(clippy::await_holding_lock)]
    async fn resolve_with_fake_composer_path(
        bin_dir: &Path,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        let _guard = FAKE_COMPOSER_PATH_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = format!("{}:/usr/bin:/bin", bin_dir.display());
        let resolver = PhpResolver::new();
        temp_env::async_with_vars([("PATH", Some(path.as_str()))], async {
            resolver.resolve(graph, ctx).await
        })
        .await
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resolve_with_composer_exec_succeeds() {
        let bin_dir = tempfile::tempdir().unwrap();
        std::fs::write(bin_dir.path().join("lock.tpl"), sample_lock())
            .unwrap();
        write_fake_composer(
            bin_dir.path(),
            "#!/bin/sh\nDIR=$(dirname \"$0\")\nif [ \"$1\" = \"--version\" ]; then echo 2.0.0; exit 0; fi\ncp \"$DIR/lock.tpl\" composer.lock\nexit 0\n",
        );

        let proj = tempfile::tempdir().unwrap();
        std::fs::write(
            proj.path().join("composer.json"),
            r#"{"require":{"symfony/http-foundation":"^6.4"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "symfony/http-foundation".into(),
                version: "^6.4".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(proj.path().join("composer.json")),
        };
        let ctx = ResolveContext {
            allow_dependency_code_execution: true,
            ..Default::default()
        };
        let result =
            resolve_with_fake_composer_path(bin_dir.path(), &graph, &ctx)
                .await
                .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert!(
            result
                .packages
                .iter()
                .any(|p| p.name == "symfony/http-foundation")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resolve_with_composer_failure_falls_back() {
        let bin_dir = tempfile::tempdir().unwrap();
        write_fake_composer(
            bin_dir.path(),
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 2; exit 0; fi\necho fail >&2\nexit 1\n",
        );
        let proj = tempfile::tempdir().unwrap();
        std::fs::write(
            proj.path().join("composer.json"),
            r#"{"require":{"a/b":"1.0.0"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "a/b".into(),
                version: "1.0.0".into(),
                ecosystem: Some(PACKAGIST_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(proj.path().join("composer.json")),
        };
        let ctx = ResolveContext {
            allow_dependency_code_execution: true,
            allow_direct_only_fallback: true,
            ..Default::default()
        };
        let result =
            resolve_with_fake_composer_path(bin_dir.path(), &graph, &ctx)
                .await
                .unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    }

    #[cfg(unix)]
    #[test]
    fn no_composer_on_empty_path() {
        let _guard = FAKE_COMPOSER_PATH_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        temp_env::with_var("PATH", Some("/nonexistent-vlz-path"), || {
            assert!(!php_package_manager_available());
        });
    }
}
