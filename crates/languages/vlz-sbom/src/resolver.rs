// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Identity resolver for SBOM inventory (already pinned; FR-038 / FR-022).

use async_trait::async_trait;
use std::path::Path;

use vlz_manifest_parser::{
    DependencyGraph, ResolutionDepth, ResolveContext, ResolveResult, Resolver,
    ResolverError,
};

use crate::names::SBOM_LANGUAGE_NAME;

/// Resolver that returns SBOM packages as full transitive coverage.
#[derive(Debug, Default)]
pub struct SbomResolver;

impl SbomResolver {
    /// Create an SBOM identity resolver.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Resolver for SbomResolver {
    fn language_name(&self) -> &'static str {
        SBOM_LANGUAGE_NAME
    }

    async fn resolve(
        &self,
        graph: &DependencyGraph,
        _ctx: &ResolveContext,
    ) -> Result<ResolveResult, ResolverError> {
        Ok(ResolveResult {
            packages: graph.packages.clone(),
            depth: ResolutionDepth::Transitive,
            direct_only_reason: None,
            ..Default::default()
        })
    }

    fn package_manager_available(&self) -> bool {
        true
    }

    fn package_manager_hint(&self) -> &'static str {
        "SBOM inventory does not require a package manager."
    }

    fn manifest_needs_package_manager(
        &self,
        _manifest_path: &Path,
        _ctx: &ResolveContext,
    ) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::{PYPI_ECOSYSTEM, Package};

    #[tokio::test]
    async fn resolve_returns_transitive_packages() {
        let graph = DependencyGraph {
            packages: vec![Package {
                name: "requests".to_string(),
                version: "2.31.0".to_string(),
                ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
            }],
            parsed_dependencies: Vec::new(),
            manifest_path: None,
        };
        let result = SbomResolver::new()
            .resolve(&graph, &ResolveContext::default())
            .await
            .unwrap();
        assert_eq!(result.depth, ResolutionDepth::Transitive);
        assert_eq!(result.packages.len(), 1);
        assert!(!SbomResolver::new().manifest_needs_package_manager(
            Path::new("bom.json"),
            &ResolveContext::default()
        ));
    }
}
