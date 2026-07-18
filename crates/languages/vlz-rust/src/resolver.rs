// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use vlz_db::CRATES_IO_ECOSYSTEM;

use async_trait::async_trait;
use vlz_manifest_parser::{
    CachedResolution, DependencyGraph, ResolutionDepth, ResolveContext,
    ResolveResult, Resolver, ResolverError, direct_only_result_from_graph,
    lock_declaration, require_transitive_or_fallback,
    resolve_declarations_for_packages, scan_toml_lock_stanzas,
    skip_package_manager_reason,
};

use crate::cargo_metadata::run_cargo_metadata;

/// Find Cargo.lock next to the manifest or in parent dirs (workspace root).
pub fn find_lock_file(manifest_path: &Path) -> Option<std::path::PathBuf> {
    let dir = manifest_path.parent()?;
    let lock_path = dir.join("Cargo.lock");
    if lock_path.exists() && lock_path.is_file() {
        return Some(lock_path);
    }
    dir.parent()
        .and_then(|p| find_lock_file(&p.join("Cargo.toml")))
}

type LockParseOutput = (
    Vec<vlz_db::Package>,
    HashMap<vlz_db::Package, Vec<vlz_db::PackageDeclarationLocation>>,
);

/// Parse Cargo.lock content into packages and lock declaration lines.
pub fn parse_cargo_lock_with_declarations(
    content: &str,
    lock_path: &Path,
) -> Result<LockParseOutput, vlz_manifest_parser::ParserError> {
    let packages = parse_cargo_lock(content)?;
    let stanzas =
        scan_toml_lock_stanzas(content, "[[package]]", CRATES_IO_ECOSYSTEM);
    let mut lock_declarations = HashMap::new();
    for stanza in stanzas {
        if let Some(loc) = lock_declaration(lock_path, stanza.start_line, None)
        {
            lock_declarations
                .entry(stanza.package)
                .or_insert_with(Vec::new)
                .push(loc);
        }
    }
    Ok((packages, lock_declarations))
}

/// Parse Cargo.lock content into a list of packages. Public for fuzzing.
pub fn parse_cargo_lock(
    content: &str,
) -> Result<Vec<vlz_db::Package>, vlz_manifest_parser::ParserError> {
    let value: toml::Value = toml::from_str(content).map_err(|e| {
        vlz_manifest_parser::ParserError::Parse(format!(
            "Cargo.lock parse error: {}",
            e
        ))
    })?;

    let mut packages = Vec::new();
    if let Some(arr) = value.get("package").and_then(|p| p.as_array()) {
        for entry in arr {
            if let Some(tbl) = entry.as_table()
                && let Some(name) = tbl.get("name").and_then(|n| n.as_str())
            {
                let version = tbl
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("any")
                    .to_string();
                packages.push(vlz_db::Package {
                    name: name.to_string(),
                    version,
                    ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
                });
            }
        }
    }
    Ok(packages)
}

/// Resolver that prefers Cargo.lock, falls back to graph packages.
/// Caches parsed Cargo.lock content to avoid re-reading when multiple
/// manifests share the same lock file (e.g. workspace members).
#[derive(Debug)]
pub struct CargoResolver {
    lock_cache: Mutex<HashMap<String, CachedResolution>>,
    metadata_cache: Mutex<HashMap<String, Vec<vlz_db::Package>>>,
}

impl Default for CargoResolver {
    fn default() -> Self {
        Self {
            lock_cache: Mutex::new(HashMap::new()),
            metadata_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl CargoResolver {
    /// Create a new Cargo resolver.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Returns true if cargo appears to be on PATH (FR-024).
pub fn cargo_package_manager_available() -> bool {
    std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// OS-specific hint when cargo is missing (FR-024).
pub fn cargo_package_manager_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install via: rustup (https://rustup.rs) or apt-get install cargo (Debian/Ubuntu).";
    #[cfg(target_os = "macos")]
    return "Install via: brew install rust or rustup (https://rustup.rs).";
    #[cfg(target_os = "windows")]
    return "Install Rust from https://rustup.rs/ and ensure cargo is on PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Rust and Cargo for your platform (https://rustup.rs).";
}

#[async_trait]
impl Resolver for CargoResolver {
    async fn resolve(
        &self,
        graph: &DependencyGraph,
        ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        if let Some(ref manifest_path) = graph.manifest_path
            && let Some(lock_path) = find_lock_file(manifest_path)
        {
            let cache_key = lock_path.to_string_lossy().to_string();
            if let Ok(cache) = self.lock_cache.lock()
                && let Some(cached) = cache.get(&cache_key)
                && !cached.packages.is_empty()
            {
                let package_declarations = resolve_declarations_for_packages(
                    &cached.packages,
                    graph,
                    &cached.package_declarations,
                );
                return Ok(ResolveResult {
                    packages: cached.packages.clone(),
                    depth: ResolutionDepth::Transitive,
                    direct_only_reason: None,
                    package_source_paths: cached.package_source_paths.clone(),
                    package_declarations,
                    resolved_lock_paths: vec![lock_path.clone()],
                });
            }
            if let Ok(content) = tokio::fs::read_to_string(&lock_path).await
                && let Ok((packages, lock_declarations)) =
                    parse_cargo_lock_with_declarations(&content, &lock_path)
                && !packages.is_empty()
            {
                let mut package_source_paths = HashMap::new();
                for pkg in &packages {
                    package_source_paths
                        .entry(pkg.clone())
                        .or_insert_with(Vec::new)
                        .push(lock_path.clone());
                }
                let cached = CachedResolution {
                    packages: packages.clone(),
                    package_declarations: lock_declarations.clone(),
                    package_source_paths: package_source_paths.clone(),
                };
                if let Ok(mut cache) = self.lock_cache.lock() {
                    cache.insert(cache_key, cached);
                }
                let package_declarations = resolve_declarations_for_packages(
                    &packages,
                    graph,
                    &lock_declarations,
                );
                return Ok(ResolveResult {
                    packages,
                    depth: ResolutionDepth::Transitive,
                    direct_only_reason: None,
                    package_source_paths,
                    package_declarations,
                    resolved_lock_paths: vec![lock_path],
                });
            }
        }

        if let Some(reason) = skip_package_manager_reason(ctx) {
            return Ok(direct_only_result_from_graph(graph, reason));
        }

        let manifest_path = graph
            .manifest_path
            .as_ref()
            .ok_or_else(vlz_manifest_parser::fr022_transitive_error)?;

        if !cargo_package_manager_available() {
            return require_transitive_or_fallback(graph, ctx, None);
        }

        let cache_key = manifest_path.to_string_lossy().to_string();
        if let Ok(cache) = self.metadata_cache.lock()
            && let Some(cached) = cache.get(&cache_key)
        {
            return Ok(ResolveResult {
                packages: cached.clone(),
                depth: ResolutionDepth::Transitive,
                direct_only_reason: None,
                ..Default::default()
            });
        }

        let manifest_abs = std::fs::canonicalize(manifest_path)
            .unwrap_or_else(|_| manifest_path.clone());
        match run_cargo_metadata(&manifest_abs).await {
            Ok(packages) => {
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(cache_key, packages.clone());
                }
                Ok(ResolveResult {
                    packages,
                    depth: ResolutionDepth::Transitive,
                    direct_only_reason: None,
                    ..Default::default()
                })
            }
            Err(err) => require_transitive_or_fallback(graph, ctx, Some(err)),
        }
    }

    fn package_manager_available(&self) -> bool {
        cargo_package_manager_available()
    }

    fn package_manager_hint(&self) -> &'static str {
        cargo_package_manager_hint()
    }

    fn language_name(&self) -> &'static str {
        "rust"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Avoid picking up the workspace `Cargo.lock` when `TMPDIR` is under the repo.
    fn isolated_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("vlz-rust-resolver-test-")
            .tempdir_in("/tmp")
            .unwrap()
    }

    #[test]
    fn find_lock_file_same_dir() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp).unwrap();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(tmp.join("Cargo.lock"), "version = 3\n").unwrap();

        let found = find_lock_file(tmp.join("Cargo.toml").as_path());
        assert_eq!(found.as_deref(), Some(tmp.join("Cargo.lock").as_path()));
    }

    #[test]
    fn parse_cargo_lock_packages() {
        let content = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tokio"
version = "1.0"
"#;
        let packages = parse_cargo_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "serde" && p.version == "1.0.0")
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "tokio" && p.version == "1.0")
        );
    }

    #[test]
    fn cargo_package_manager_hint_non_empty() {
        let hint = cargo_package_manager_hint();
        assert!(!hint.is_empty());
        assert!(
            hint.contains("cargo")
                || hint.contains("Rust")
                || hint.contains("rustup"),
            "hint should mention cargo or Rust"
        );
    }

    #[tokio::test]
    async fn cargo_resolver_returns_fr022_when_no_manifest_path() {
        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: None,
        };
        let resolver = CargoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext::default();
        let err = resolver.resolve(&graph, &ctx).await.unwrap_err();
        assert!(
            err.to_string().contains(
                vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
            )
        );
    }

    #[tokio::test]
    async fn cargo_resolver_offline_without_lock_sets_offline_reason() {
        let dir = isolated_tempdir();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("Cargo.toml"),
            r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: false,
            ..Default::default()
        };
        let resolved = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(resolved.packages.len(), 1);
        assert_eq!(
            resolved.direct_only_reason,
            Some(vlz_manifest_parser::DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[tokio::test]
    async fn cargo_resolver_offline_with_lock_stays_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\nname = \"test\"\n")
            .unwrap();
        std::fs::write(
            tmp.join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "serde"
version = "1.0.2"
"#,
        )
        .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext {
            skip_pip_resolution: true,
            ..Default::default()
        };
        let resolved = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(
            resolved.depth,
            vlz_manifest_parser::ResolutionDepth::Transitive
        );
        assert_eq!(resolved.direct_only_reason, None);
        assert_eq!(resolved.packages.len(), 1);
    }

    #[tokio::test]
    async fn cargo_resolver_benchmark_without_lock_sets_benchmark_reason() {
        let dir = isolated_tempdir();
        let tmp = dir.path();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\nname = \"test\"\n")
            .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext {
            skip_pip_resolution: true,
            benchmark_mode: true,
            ..Default::default()
        };
        let resolved = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(
            resolved.direct_only_reason,
            Some(vlz_manifest_parser::DIRECT_ONLY_REASON_BENCHMARK)
        );
    }

    #[tokio::test]
    async fn cargo_resolver_uses_lock_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp).unwrap();
        std::fs::write(
            tmp.join("Cargo.toml"),
            r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "serde"
version = "1.0.2"

[[package]]
name = "serde_derive"
version = "1.0.2"
"#,
        )
        .unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext::default();
        let resolved = resolver.resolve(&graph, &ctx).await.unwrap();
        assert_eq!(resolved.packages.len(), 2);
        assert_eq!(
            resolved.depth,
            vlz_manifest_parser::ResolutionDepth::Transitive
        );
        assert_eq!(resolved.direct_only_reason, None);
        assert!(
            resolved
                .packages
                .iter()
                .any(|p| p.name == "serde" && p.version == "1.0.2")
        );
        assert!(resolved.packages.iter().any(|p| p.name == "serde_derive"));
    }

    #[tokio::test]
    async fn cargo_resolver_empty_lock_falls_through_to_metadata_or_fr022() {
        let dir = isolated_tempdir();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp).unwrap();
        std::fs::write(
            tmp.join("Cargo.toml"),
            r#"[package]
name = "test"
version = "0.1.0"
"#,
        )
        .unwrap();
        std::fs::write(tmp.join("Cargo.lock"), "version = 3\n").unwrap();

        let graph = DependencyGraph {
            packages: vec![vlz_db::Package {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(tmp.join("Cargo.toml")),
        };
        let resolver = CargoResolver::new();
        let ctx = vlz_manifest_parser::ResolveContext::default();
        match resolver.resolve(&graph, &ctx).await {
            Ok(resolved) => {
                assert_eq!(
                    resolved.depth,
                    vlz_manifest_parser::ResolutionDepth::Transitive
                );
            }
            Err(err) => {
                assert!(err.to_string().contains(
                    vlz_manifest_parser::FR_022_TRANSITIVE_ERROR_MESSAGE
                ));
            }
        }
    }

    #[test]
    fn find_lock_file_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::create_dir_all(tmp.join("crates/foo")).unwrap();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(tmp.join("Cargo.lock"), "version = 3\n").unwrap();
        std::fs::write(tmp.join("crates/foo/Cargo.toml"), "[package]\n")
            .unwrap();

        let found =
            find_lock_file(tmp.join("crates/foo/Cargo.toml").as_path());
        assert_eq!(found.as_deref(), Some(tmp.join("Cargo.lock").as_path()));
    }

    #[test]
    fn parse_cargo_lock_package_without_version() {
        let content = r#"
version = 3

[[package]]
name = "noversion"
"#;
        let packages = parse_cargo_lock(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "noversion");
        assert_eq!(packages[0].version, "any");
    }

    #[test]
    fn parse_cargo_lock_malformed_returns_error() {
        let content = "invalid {{{";
        let err = parse_cargo_lock(content).unwrap_err();
        assert!(format!("{:?}", err).contains("parse"));
    }

    #[test]
    fn resolver_package_manager_available_and_hint() {
        let resolver = CargoResolver::new();
        let _ = resolver.package_manager_available();
        let hint = resolver.package_manager_hint();
        assert!(!hint.is_empty());
    }
}
