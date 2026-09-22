// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod csproj;
mod directory_packages_props;
mod local_lock;
mod packages_config;
mod packages_lock;

use async_trait::async_trait;
use std::path::Path;

use vlz_manifest_parser::{
    DependencyGraph, ParsedDependency, Parser, ParserError,
};

pub use csproj::{
    DOTNET_MANIFEST_MAX_BYTES, parse_csproj, parse_csproj_with_declarations,
};
pub use directory_packages_props::{
    graph_with_central_package_versions, load_central_package_versions,
    parse_directory_packages_props,
};
pub use local_lock::{
    parse_deps_json, parse_deps_json_with_declarations,
    parse_project_assets_json, parse_project_assets_json_with_declarations,
};
pub use packages_config::{
    parse_packages_config, parse_packages_config_with_declarations,
};
pub use packages_lock::{
    is_nuget_package_name, parse_packages_lock,
    parse_packages_lock_with_declarations,
};

use crate::finder::{is_dotnet_manifest_name, is_packages_config_name};
use crate::lock_names::is_dotnet_lock_file;

fn parse_lock_content_with_declarations(
    content: &str,
    manifest: &Path,
    name: &str,
) -> Result<(Vec<vlz_db::Package>, Vec<ParsedDependency>), ParserError> {
    if name.eq_ignore_ascii_case("packages.lock.json") {
        parse_packages_lock_with_declarations(content, manifest)
    } else if name.eq_ignore_ascii_case("project.assets.json") {
        parse_project_assets_json_with_declarations(content, manifest)
    } else if name.ends_with(".deps.json") {
        parse_deps_json_with_declarations(content, manifest)
    } else {
        Ok((Vec::new(), Vec::new()))
    }
}

/// Maximum accepted size for packages.lock.json files.
pub const DOTNET_LOCK_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Parser for .NET project files and `packages.lock.json`.
#[derive(Debug, Default)]
pub struct DotnetManifestParser;

impl DotnetManifestParser {
    /// Create a new .NET / NuGet manifest parser.
    pub fn new() -> Self {
        Self
    }
}

async fn read_capped(
    path: &Path,
    max_bytes: u64,
) -> Result<String, ParserError> {
    if tokio::fs::metadata(path).await?.len() > max_bytes {
        return Err(ParserError::Parse(format!(
            ".NET / NuGet file exceeds {max_bytes} byte limit"
        )));
    }
    Ok(tokio::fs::read_to_string(path).await?)
}

#[async_trait]
impl Parser for DotnetManifestParser {
    fn language_name(&self) -> &'static str {
        "dotnet"
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let name = manifest
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let content = if is_dotnet_manifest_name(name)
            || is_packages_config_name(name)
        {
            read_capped(manifest, DOTNET_MANIFEST_MAX_BYTES).await?
        } else if is_dotnet_lock_file(name) {
            read_capped(manifest, DOTNET_LOCK_MAX_BYTES).await?
        } else {
            tokio::fs::read_to_string(manifest).await?
        };
        let (packages, parsed_dependencies) = if is_dotnet_manifest_name(name)
        {
            parse_csproj_with_declarations(&content, manifest)?
        } else if is_packages_config_name(name) {
            parse_packages_config_with_declarations(&content, manifest)?
        } else if is_dotnet_lock_file(name) {
            parse_lock_content_with_declarations(&content, manifest, name)?
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(DependencyGraph {
            packages,
            parsed_dependencies,
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("App.csproj");
        std::fs::write(
            &path,
            vec![b'x'; DOTNET_MANIFEST_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(DotnetManifestParser::new().parse(&path).await.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("packages.lock.json");
        std::fs::write(&path, vec![b'x'; DOTNET_LOCK_MAX_BYTES as usize + 1])
            .unwrap();
        assert!(DotnetManifestParser::new().parse(&path).await.is_err());
    }

    #[tokio::test]
    async fn parses_csproj_and_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("App.csproj");
        std::fs::write(
            &manifest,
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
"#,
        )
        .unwrap();
        let graph =
            DotnetManifestParser::new().parse(&manifest).await.unwrap();
        assert_eq!(graph.packages.len(), 1);

        let other = dir.path().join("notes.txt");
        std::fs::write(&other, "hello\n").unwrap();
        let empty = DotnetManifestParser::new().parse(&other).await.unwrap();
        assert!(empty.packages.is_empty());
    }

    #[test]
    fn language_name_is_stable() {
        assert_eq!(DotnetManifestParser::new().language_name(), "dotnet");
    }
}
