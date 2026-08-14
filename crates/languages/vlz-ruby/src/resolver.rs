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

use crate::lock_names::lock_name_for_manifest;
use crate::parser::{
    RUBY_LOCK_MAX_BYTES, parse_gemfile_lock_with_declarations,
};

const BUNDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Find the lock basename paired with this manifest (parent walk to scan root).
pub fn find_ruby_lock_file(
    manifest_path: &Path,
    scan_root: Option<&Path>,
) -> Option<PathBuf> {
    use crate::lock_names::lock_names_for_manifest;
    let lock_names = lock_names_for_manifest(manifest_path)?;
    let mut dir = manifest_path.parent()?.to_path_buf();
    loop {
        if scan_root.is_some_and(|root| !dir.starts_with(root)) {
            return None;
        }
        for lock_name in lock_names {
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
    if metadata.len() > RUBY_LOCK_MAX_BYTES {
        return Err(ResolverError::Resolve(format!(
            "Ruby lock exceeds {} byte limit",
            RUBY_LOCK_MAX_BYTES
        )));
    }
    let content = std::fs::read_to_string(path).map_err(ResolverError::Io)?;
    let (packages, parsed) =
        parse_gemfile_lock_with_declarations(&content, path)
            .map_err(|error| ResolverError::Resolve(error.to_string()))?;
    Ok(CachedResolution {
        packages,
        package_declarations: lock_declarations_from_parsed(&parsed),
        package_source_paths: HashMap::new(),
    })
}

pub fn ruby_package_manager_available() -> bool {
    vlz_manifest_parser::package_manager_command_ok("bundle", &["--version"])
}

pub fn ruby_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: apt-get install ruby bundler (Debian/Ubuntu) or dnf install ruby rubygem-bundler (Fedora/RHEL).";
    #[cfg(target_os = "macos")]
    return "Install via: brew install ruby (then gem install bundler if needed).";
    #[cfg(target_os = "windows")]
    return "Install Ruby from https://rubyinstaller.org/ and ensure bundle is on PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Ruby and Bundler for your platform (gem install bundler).";
}

async fn ephemeral_bundle_lock(
    manifest_path: &Path,
) -> Result<CachedResolution, ResolverError> {
    if !ruby_package_manager_available() {
        return Err(ResolverError::Resolve(
            "bundle is not available on PATH".into(),
        ));
    }
    let temp = tempfile::Builder::new()
        .prefix("vlz-ruby-")
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

    let source_name = manifest_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let bundle_manifest = if source_name.ends_with(".gemspec") {
        let gemspec_name = manifest_path.file_name().ok_or_else(|| {
            ResolverError::Resolve("gemspec has no file name".into())
        })?;
        std::fs::copy(manifest_path, temp.path().join(gemspec_name))
            .map_err(ResolverError::Io)?;
        let path = temp.path().join("Gemfile");
        std::fs::write(&path, "source \"https://rubygems.org\"\ngemspec\n")
            .map_err(ResolverError::Io)?;
        path
    } else {
        let destination = temp.path().join(source_name);
        std::fs::copy(manifest_path, &destination)
            .map_err(ResolverError::Io)?;
        destination
    };

    let mut command = tokio::process::Command::new("bundle");
    command
        .arg("lock")
        .current_dir(temp.path())
        .kill_on_drop(true)
        .env_remove("BUNDLE_PATH")
        .env_remove("BUNDLE_APP_CONFIG")
        .env("BUNDLE_GEMFILE", &bundle_manifest);
    let output = tokio::time::timeout(BUNDLE_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            ResolverError::Resolve(format!(
                "bundle lock timed out after {}s",
                BUNDLE_TIMEOUT.as_secs()
            ))
        })?
        .map_err(ResolverError::Io)?;
    if !output.status.success() {
        return Err(ResolverError::Resolve(format!(
            "bundle lock failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let lock_name =
        lock_name_for_manifest(&bundle_manifest).ok_or_else(|| {
            ResolverError::Resolve(
                "cannot determine generated lock name".into(),
            )
        })?;
    let lock = temp.path().join(lock_name);
    if !lock.is_file() {
        return Err(ResolverError::Resolve(
            "bundle lock did not produce a paired lock file".into(),
        ));
    }
    parse_lock_path(&lock)
}

#[derive(Debug, Default)]
pub struct RubyResolver {
    lock_cache: Mutex<HashMap<PathBuf, CachedResolution>>,
}

impl RubyResolver {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Resolver for RubyResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        if let Some(manifest) = graph.manifest_path.as_deref()
            && let Some(lock_path) =
                find_ruby_lock_file(manifest, ctx.scan_root.as_deref())
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
            // Empty lock: fall through to offline/FR-022/gated bundle lock.
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
        match ephemeral_bundle_lock(manifest).await {
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
        ruby_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        ruby_package_manager_hint()
    }

    fn manifest_needs_package_manager(
        &self,
        manifest_path: &Path,
        ctx: &ResolveContext,
    ) -> bool {
        find_ruby_lock_file(manifest_path, ctx.scan_root.as_deref()).is_none()
    }

    fn language_name(&self) -> &'static str {
        "ruby"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_walk_stops_at_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let scan = dir.path().join("scan");
        let nested = scan.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("Gemfile.lock"), "GEM\n").unwrap();
        std::fs::write(nested.join("Gemfile"), "").unwrap();
        assert!(
            find_ruby_lock_file(&nested.join("Gemfile"), Some(&scan))
                .is_none()
        );
    }

    #[test]
    fn gemspec_prefers_gemfile_lock_then_gems_locked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("demo.gemspec"), "").unwrap();
        std::fs::write(root.join("gems.locked"), "GEM\n").unwrap();
        let found =
            find_ruby_lock_file(&root.join("demo.gemspec"), Some(root))
                .unwrap();
        assert!(found.ends_with("gems.locked"));
        std::fs::write(root.join("Gemfile.lock"), "GEM\n").unwrap();
        let found =
            find_ruby_lock_file(&root.join("demo.gemspec"), Some(root))
                .unwrap();
        assert!(found.ends_with("Gemfile.lock"));
    }

    #[tokio::test]
    async fn lockless_without_exec_requires_transitive_or_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem \"rack\"\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = RubyResolver::new().resolve(&graph, &ctx).await.unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            ) || err.to_string().contains("Unable to detect transitive")
        );
    }

    #[tokio::test]
    async fn empty_lock_falls_through_to_fr022() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem \"rack\"\n").unwrap();
        std::fs::write(dir.path().join("Gemfile.lock"), "GEM\n  specs:\n")
            .unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = RubyResolver::new().resolve(&graph, &ctx).await.unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            )
        );
    }

    #[tokio::test]
    async fn offline_lockless_returns_direct_only() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem \"rack\"\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            skip_pip_resolution: true,
            ..Default::default()
        };
        let result = RubyResolver::new().resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
        assert!(result.direct_only_reason.is_some());
    }

    #[tokio::test]
    async fn allow_direct_only_fallback_without_exec() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem \"rack\"\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            allow_direct_only_fallback: true,
            ..Default::default()
        };
        let result = RubyResolver::new().resolve(&graph, &ctx).await.unwrap();
        assert_eq!(result.depth, ResolutionDepth::DirectOnly);
    }

    #[test]
    fn parent_walk_finds_paired_lock() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("apps").join("web");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            "GEM\n  specs:\n    rack (2.2.8)\n",
        )
        .unwrap();
        std::fs::write(nested.join("Gemfile"), "gem 'rack'\n").unwrap();
        let found =
            find_ruby_lock_file(&nested.join("Gemfile"), Some(dir.path()))
                .unwrap();
        assert!(found.ends_with("Gemfile.lock"));
    }

    #[test]
    fn manifest_needs_package_manager_tracks_lock() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "").unwrap();
        let resolver = RubyResolver::new();
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert!(resolver.manifest_needs_package_manager(&gemfile, &ctx));
        std::fs::write(dir.path().join("Gemfile.lock"), "GEM\n").unwrap();
        assert!(!resolver.manifest_needs_package_manager(&gemfile, &ctx));
    }

    #[test]
    fn resolver_metadata_is_stable() {
        let resolver = RubyResolver::new();
        assert_eq!(resolver.language_name(), "ruby");
        assert!(!resolver.package_manager_hint().is_empty());
        let _ = resolver.package_manager_available();
    }

    #[test]
    fn find_lock_returns_none_when_manifest_outside_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let scan = dir.path().join("scan");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&scan).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("Gemfile"), "").unwrap();
        std::fs::write(outside.join("Gemfile.lock"), "GEM\n").unwrap();
        assert!(
            find_ruby_lock_file(&outside.join("Gemfile"), Some(&scan))
                .is_none()
        );
    }

    #[tokio::test]
    async fn oversized_lock_errors_during_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem 'rack'\n").unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            vec![b'x'; RUBY_LOCK_MAX_BYTES as usize + 1],
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = RubyResolver::new().resolve(&graph, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("byte limit"));
    }

    #[tokio::test]
    async fn lock_cache_hit_on_second_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem 'rack'\n").unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            "GEM\n  specs:\n    rack (2.2.8)\n",
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let ctx = ResolveContext {
            scan_root: Some(dir.path().to_path_buf()),
            skip_pip_resolution: true,
            ..Default::default()
        };
        let resolver = RubyResolver::new();
        let first = resolver.resolve(&graph, &ctx).await.unwrap();
        let second = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(first.packages, second.packages);
        assert_eq!(second.depth, ResolutionDepth::Transitive);
    }

    #[cfg(unix)]
    fn write_fake_bundle(bin_dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(bin_dir).unwrap();
        let bundle = bin_dir.join("bundle");
        std::fs::write(
            &bundle,
            "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then exit 0; fi\n\
             if [ \"$1\" = \"lock\" ]; then\n\
               printf 'GEM\\n  specs:\\n    rack (2.2.8)\\n' > Gemfile.lock\n\
               printf 'GEM\\n  specs:\\n    rack (2.2.8)\\n' > gems.locked\n\
               exit 0\n\
             fi\n\
             echo \"unexpected: $*\" >&2\n\
             exit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(
            &bundle,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn gated_bundle_lock_with_fake_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        write_fake_bundle(&bin);
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let gemfile = project.join("Gemfile");
        std::fs::write(&gemfile, "gem 'rack'\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        temp_env::async_with_vars([("PATH", Some(path.as_str()))], async {
            let ctx = ResolveContext {
                scan_root: Some(project.clone()),
                allow_dependency_code_execution: true,
                ..Default::default()
            };
            let result =
                RubyResolver::new().resolve(&graph, &ctx).await.unwrap();
            assert_eq!(result.depth, ResolutionDepth::Transitive);
            assert!(
                result
                    .packages
                    .iter()
                    .any(|p| p.name == "rack" && p.version == "2.2.8")
            );
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn gated_bundle_lock_gemspec_with_fake_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        write_fake_bundle(&bin);
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let gemspec = project.join("demo.gemspec");
        std::fs::write(
            &gemspec,
            "Gem::Specification.new do |s|\n  s.add_dependency 'rack'\nend\n",
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemspec),
        };
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        temp_env::async_with_vars([("PATH", Some(path.as_str()))], async {
            let ctx = ResolveContext {
                scan_root: Some(project.clone()),
                allow_dependency_code_execution: true,
                ..Default::default()
            };
            let result =
                RubyResolver::new().resolve(&graph, &ctx).await.unwrap();
            assert_eq!(result.depth, ResolutionDepth::Transitive);
            assert!(result.packages.iter().any(|p| p.name == "rack"));
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn gated_bundle_missing_falls_back_or_errors() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem 'rack'\n").unwrap();
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "rack".into(),
                version: "*".into(),
                ecosystem: Some(crate::RUBYGEMS_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(gemfile),
        };
        temp_env::async_with_vars([("PATH", Some(""))], async {
            let ctx = ResolveContext {
                scan_root: Some(dir.path().to_path_buf()),
                allow_dependency_code_execution: true,
                ..Default::default()
            };
            let err =
                RubyResolver::new().resolve(&graph, &ctx).await.unwrap_err();
            assert!(
                err.to_string().contains("bundle")
                    || err.to_string().contains(
                        vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
                    )
            );
        })
        .await;
    }
}
