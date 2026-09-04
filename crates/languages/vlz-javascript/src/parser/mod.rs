// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod bun_lock;
mod npm_lock;
mod package_json;
mod pnpm_lock;
mod yarn_lock;

use async_trait::async_trait;
use std::path::Path;

use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

pub use bun_lock::{parse_bun_lock, parse_bun_lock_with_declarations};
pub use npm_lock::{parse_npm_lock, parse_npm_lock_with_declarations};
pub use package_json::{
    PackageJsonMeta, parse_package_json, parse_package_json_with_meta,
};
pub use pnpm_lock::{parse_pnpm_lock, parse_pnpm_lock_with_declarations};
pub use yarn_lock::{parse_yarn_lock, parse_yarn_lock_with_declarations};

/// Parser for JavaScript/TypeScript `package.json` manifests.
#[derive(Debug, Default)]
pub struct JsManifestParser;

impl JsManifestParser {
    /// Create a new package.json parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for JsManifestParser {
    fn language_name(&self) -> &'static str {
        "javascript"
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let content = tokio::fs::read_to_string(manifest).await?;
        let basename =
            manifest.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let (packages, parsed) = match basename {
            "package-lock.json" | "npm-shrinkwrap.json" => {
                parse_npm_lock_with_declarations(&content, manifest)?
            }
            "yarn.lock" => {
                parse_yarn_lock_with_declarations(&content, manifest)?
            }
            "pnpm-lock.yaml" => {
                parse_pnpm_lock_with_declarations(&content, manifest)?
            }
            "bun.lock" => {
                parse_bun_lock_with_declarations(&content, manifest)?
            }
            _ => package_json::parse_package_json_with_declarations(
                &content, manifest,
            )?,
        };
        Ok(DependencyGraph {
            packages,
            parsed_dependencies: parsed,
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_name_and_default() {
        let parser = JsManifestParser;
        assert_eq!(parser.language_name(), "javascript");
        assert_eq!(JsManifestParser::new().language_name(), "javascript");
    }
}
