// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
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

use crate::lock_names::{list_lock_files_in_dir, select_lock_file};
use crate::parser::{
    parse_bun_lock_with_declarations, parse_npm_lock_with_declarations,
    parse_package_json_with_meta, parse_pnpm_lock_with_declarations,
    parse_yarn_lock_with_declarations,
};

/// Default timeout for package-manager subprocesses.
const PM_TIMEOUT: Duration = Duration::from_secs(120);

/// Find a usable lock file next to the manifest or in parent directories.
///
/// When `scan_root` is set, the walk stops at that directory and never
/// uses locks outside the scanned tree.
pub fn find_js_lock_file(
    manifest_path: &Path,
    package_manager: Option<&str>,
    scan_root: Option<&Path>,
) -> Option<(PathBuf, Vec<String>)> {
    let mut dir = manifest_path.parent()?.to_path_buf();
    loop {
        if let Some(root) = scan_root
            && !dir.starts_with(root)
        {
            break;
        }
        let candidates = list_lock_files_in_dir(&dir);
        if let Some(chosen) = select_lock_file(&candidates, package_manager) {
            return Some(chosen);
        }
        if let Some(root) = scan_root
            && dir == root
        {
            break;
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Parse a lock file by basename into packages + declarations.
fn parse_lock_path(
    lock_path: &Path,
) -> Result<CachedResolution, ResolverError> {
    let content =
        std::fs::read_to_string(lock_path).map_err(ResolverError::Io)?;
    let name = lock_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let (packages, parsed) = match name {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            parse_npm_lock_with_declarations(&content, lock_path)
                .map_err(|e| ResolverError::Resolve(e.to_string()))?
        }
        "yarn.lock" => parse_yarn_lock_with_declarations(&content, lock_path)
            .map_err(|e| ResolverError::Resolve(e.to_string()))?,
        "pnpm-lock.yaml" => {
            parse_pnpm_lock_with_declarations(&content, lock_path)
                .map_err(|e| ResolverError::Resolve(e.to_string()))?
        }
        "bun.lock" => parse_bun_lock_with_declarations(&content, lock_path)
            .map_err(|e| ResolverError::Resolve(e.to_string()))?,
        _ => {
            return Err(ResolverError::Resolve(format!(
                "unsupported lock file: {name}"
            )));
        }
    };
    let lock_declarations = lock_declarations_from_parsed(&parsed);
    Ok(CachedResolution {
        packages,
        package_declarations: lock_declarations,
        package_source_paths: HashMap::new(),
    })
}

/// Public parse helpers for fuzz targets (re-exported from parser).
#[allow(unused_imports)]
pub use crate::parser::{
    parse_bun_lock as fuzz_parse_bun_lock,
    parse_npm_lock as fuzz_parse_npm_lock,
    parse_pnpm_lock as fuzz_parse_pnpm_lock,
    parse_yarn_lock as fuzz_parse_yarn_lock,
};

/// Resolver: adjacent/parent lock preferred; PM only with SEC-023 opt-in.
#[derive(Debug, Default)]
pub struct JsResolver {
    lock_cache: Mutex<HashMap<String, CachedResolution>>,
}

impl JsResolver {
    /// Create a new JavaScript resolver.
    pub fn new() -> Self {
        Self::default()
    }
}

/// True when npm appears on PATH (default PM for FR-024).
pub fn js_package_manager_available() -> bool {
    ["npm", "yarn", "pnpm", "bun"].iter().any(|bin| {
        std::process::Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// OS-specific hint when no JS package manager is found (FR-024).
pub fn js_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install Node.js/npm via: apt-get install npm (Debian/Ubuntu) or dnf install nodejs (Fedora), or install yarn/pnpm/bun for your stack.";
    #[cfg(target_os = "macos")]
    return "Install via: brew install node (npm), or yarn/pnpm/bun as needed.";
    #[cfg(target_os = "windows")]
    return "Install Node.js from https://nodejs.org/ (includes npm), or yarn/pnpm/bun.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Node.js/npm or yarn/pnpm/bun for your platform.";
}

fn read_package_manager_field(manifest_path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(manifest_path).ok()?;
    parse_package_json_with_meta(&content)
        .ok()?
        .1
        .package_manager
}

fn choose_pm_binary(package_manager: Option<&str>) -> Option<&'static str> {
    if let Some(pm) = package_manager {
        let name = pm.split('@').next().unwrap_or(pm).to_ascii_lowercase();
        let bin = match name.as_str() {
            "npm" => "npm",
            "yarn" => "yarn",
            "pnpm" => "pnpm",
            "bun" => "bun",
            _ => return first_available_pm(),
        };
        if command_available(bin) {
            return Some(bin);
        }
    }
    first_available_pm()
}

fn first_available_pm() -> Option<&'static str> {
    ["npm", "yarn", "pnpm", "bun"]
        .into_iter()
        .find(|&bin| command_available(bin))
}

fn command_available(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn ephemeral_pm_resolve(
    manifest_path: &Path,
    package_manager: Option<&str>,
) -> Result<CachedResolution, ResolverError> {
    let bin = choose_pm_binary(package_manager).ok_or_else(|| {
        ResolverError::Resolve("no JavaScript package manager on PATH".into())
    })?;
    let tmp = tempfile::Builder::new()
        .prefix("vlz-js-")
        .tempdir()
        .map_err(ResolverError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            tmp.path(),
            std::fs::Permissions::from_mode(0o700),
        );
    }
    let src =
        std::fs::read_to_string(manifest_path).map_err(ResolverError::Io)?;
    let dest = tmp.path().join("package.json");
    std::fs::write(&dest, src).map_err(ResolverError::Io)?;

    let mut cmd = tokio::process::Command::new(bin);
    cmd.current_dir(tmp.path()).kill_on_drop(true);
    // Prefer lock-only / ignore-scripts style invocation.
    match bin {
        "npm" => {
            cmd.args([
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ]);
        }
        "yarn" => {
            cmd.args(["install", "--mode=skip-build", "--ignore-scripts"]);
        }
        "pnpm" => {
            cmd.args(["install", "--lockfile-only", "--ignore-scripts"]);
        }
        "bun" => {
            cmd.args(["install", "--lockfile-only", "--ignore-scripts"]);
        }
        _ => {}
    }
    // Discourage lifecycle scripts via env when possible.
    cmd.env("npm_config_ignore_scripts", "true");
    cmd.env("NPM_CONFIG_IGNORE_SCRIPTS", "true");

    let output = tokio::time::timeout(PM_TIMEOUT, cmd.output())
        .await
        .map_err(|_| {
            ResolverError::Resolve(format!(
                "{bin} timed out after {}s",
                PM_TIMEOUT.as_secs()
            ))
        })?
        .map_err(ResolverError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ResolverError::Resolve(format!(
            "{bin} failed: {}",
            stderr.trim()
        )));
    }

    let candidates = list_lock_files_in_dir(tmp.path());
    let (lock_path, _) = select_lock_file(&candidates, package_manager)
        .ok_or_else(|| {
            ResolverError::Resolve(
                "package manager did not produce a lock file".into(),
            )
        })?;
    parse_lock_path(&lock_path)
}

#[async_trait]
impl Resolver for JsResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        if let Some(reason) = skip_package_manager_reason(ctx) {
            return Ok(direct_only_result_from_graph(graph, reason));
        }

        let Some(manifest_path) = graph.manifest_path.as_ref() else {
            return Err(fr022_transitive_error());
        };

        let pm_field = read_package_manager_field(manifest_path);
        let scan_root = ctx.scan_root.as_deref();
        if let Some((lock_path, all_names)) =
            find_js_lock_file(manifest_path, pm_field.as_deref(), scan_root)
        {
            let cache_key = lock_path.to_string_lossy().to_string();
            let cached = {
                let cache = self.lock_cache.lock().map_err(|e| {
                    ResolverError::Other(format!("lock cache lock: {e}"))
                })?;
                cache.get(&cache_key).cloned()
            };
            let resolution = if let Some(c) = cached {
                c
            } else {
                let parsed = parse_lock_path(&lock_path)?;
                if let Ok(mut cache) = self.lock_cache.lock() {
                    cache.insert(cache_key, parsed.clone());
                }
                parsed
            };

            let package_declarations = resolve_declarations_for_packages(
                &resolution.packages,
                graph,
                &resolution.package_declarations,
            );
            let mut result = ResolveResult {
                packages: resolution.packages,
                depth: ResolutionDepth::Transitive,
                direct_only_reason: None,
                package_declarations,
                resolved_lock_paths: vec![lock_path],
                ..Default::default()
            };
            if all_names.len() > 1 {
                // Multi-lock warning is emitted by package_resolve when
                // resolved_lock_paths.len() > 1; surface all names via paths
                // under the same parent for the warning helper.
                if let Some(dir) = result.resolved_lock_paths[0].parent() {
                    result.resolved_lock_paths = all_names
                        .iter()
                        .map(|n| dir.join(n))
                        .filter(|p| p.is_file())
                        .collect();
                    if result.resolved_lock_paths.is_empty() {
                        // keep at least the chosen path
                        if let Some((lock_path, _)) = find_js_lock_file(
                            manifest_path,
                            pm_field.as_deref(),
                            scan_root,
                        ) {
                            result.resolved_lock_paths = vec![lock_path];
                        }
                    }
                }
            }
            return Ok(result);
        }

        // No lock: SEC-023 -- do not spawn PM unless explicitly allowed.
        if !ctx.allow_dependency_code_execution {
            return require_transitive_or_fallback(graph, ctx, None);
        }

        match ephemeral_pm_resolve(manifest_path, pm_field.as_deref()).await {
            Ok(resolution) => {
                let package_declarations = resolve_declarations_for_packages(
                    &resolution.packages,
                    graph,
                    &resolution.package_declarations,
                );
                Ok(ResolveResult {
                    packages: resolution.packages,
                    depth: ResolutionDepth::Transitive,
                    direct_only_reason: None,
                    package_declarations,
                    ..Default::default()
                })
            }
            Err(e) => require_transitive_or_fallback(graph, ctx, Some(e)),
        }
    }

    fn package_manager_available(&self) -> bool {
        js_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        js_package_manager_hint()
    }

    fn manifest_needs_package_manager(
        &self,
        manifest_path: &Path,
        ctx: &ResolveContext,
    ) -> bool {
        let pm = read_package_manager_field(manifest_path);
        find_js_lock_file(
            manifest_path,
            pm.as_deref(),
            ctx.scan_root.as_deref(),
        )
        .is_none()
    }

    fn language_name(&self) -> &'static str {
        "javascript"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::{NPM_ECOSYSTEM, Package};

    #[test]
    fn find_js_lock_file_adjacent() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(tmp.join("package.json"), r#"{"name":"a"}"#).unwrap();
        std::fs::write(
            tmp.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{}}"#,
        )
        .unwrap();
        let found =
            find_js_lock_file(&tmp.join("package.json"), None, Some(tmp))
                .unwrap();
        assert!(found.0.ends_with("package-lock.json"));
    }

    #[test]
    fn find_js_lock_file_parent_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let nested = tmp.join("packages/foo");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(tmp.join("package.json"), r#"{"name":"root"}"#)
            .unwrap();
        std::fs::write(nested.join("package.json"), r#"{"name":"foo"}"#)
            .unwrap();
        std::fs::write(
            tmp.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .unwrap();
        let found =
            find_js_lock_file(&nested.join("package.json"), None, Some(tmp))
                .unwrap();
        assert!(found.0.ends_with("package-lock.json"));
    }

    #[test]
    fn find_js_lock_file_does_not_walk_above_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path();
        let scan = outside.join("project");
        let nested = scan.join("packages/foo");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            outside.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        std::fs::write(nested.join("package.json"), r#"{"name":"foo"}"#)
            .unwrap();
        assert!(
            find_js_lock_file(&nested.join("package.json"), None, Some(&scan))
                .is_none(),
            "must not use lock files above the scan root"
        );
    }

    #[test]
    fn manifest_needs_pm_false_with_lock() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(tmp.join("package.json"), r#"{"name":"a"}"#).unwrap();
        std::fs::write(
            tmp.join("yarn.lock"),
            "# yarn lockfile v1\n\nlodash@^4.0.0:\n  version \"4.17.21\"\n",
        )
        .unwrap();
        let resolver = JsResolver::new();
        assert!(!resolver.manifest_needs_package_manager(
            &tmp.join("package.json"),
            &ResolveContext::default()
        ));
    }

    #[tokio::test]
    async fn resolve_from_lock_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("package.json"),
            r#"{"name":"a","dependencies":{"lodash":"^4.17.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("package-lock.json"),
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name":"a"},
    "node_modules/lodash": {"version":"4.17.21"}
  }
}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "lodash".into(),
                version: "^4.17.0".into(),
                ecosystem: Some(NPM_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("package.json")),
        };
        let resolver = JsResolver::new();
        let result = resolver
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert!(
            result
                .packages
                .iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21")
        );
    }

    #[tokio::test]
    async fn resolve_no_lock_without_exec_exits_fr022() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("package.json"),
            r#"{"name":"a","dependencies":{"lodash":"^4.17.0"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "lodash".into(),
                version: "^4.17.0".into(),
                ecosystem: Some(NPM_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("package.json")),
        };
        let resolver = JsResolver::new();
        let err = resolver
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
    async fn resolve_offline_direct_only() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("package.json"),
            r#"{"dependencies":{"lodash":"4.17.21"}}"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "lodash".into(),
                version: "4.17.21".into(),
                ecosystem: Some(NPM_ECOSYSTEM.into()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("package.json")),
        };
        let resolver = JsResolver::new();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..Default::default()
        };
        let result = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(
            result.direct_only_reason,
            Some(vlz_manifest_parser::DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[test]
    fn parse_helpers_smoke() {
        use crate::parser::{
            parse_bun_lock, parse_npm_lock, parse_pnpm_lock, parse_yarn_lock,
        };
        let _ = parse_npm_lock("{}");
        let _ = parse_yarn_lock("# yarn lockfile v1\n");
        let _ = parse_pnpm_lock("lockfileVersion: '6.0'\npackages: {}\n");
        let _ = parse_bun_lock(r#"{"packages":{}}"#);
    }
}
