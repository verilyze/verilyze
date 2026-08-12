// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use vlz_db::{DeclarationKind, MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use crate::coordinate::{maven_package_name, parse_gav_triple};

/// Parse Gradle version catalog into packages (direct only).
pub fn parse_version_catalog(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_version_catalog_with_declarations(
        content,
        Path::new("libs.versions.toml"),
    )?
    .into_iter()
    .filter(|d| !d.package.version.is_empty())
    .map(|d| d.package)
    .collect())
}

pub fn parse_version_catalog_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    let raw: CatalogToml = toml::from_str(content).map_err(|e| {
        ParserError::Parse(format!("libs.versions.toml parse error: {e}"))
    })?;
    let versions = raw.versions.unwrap_or_default();
    let mut out = Vec::new();
    let mut line_hint: u32 = 1;

    if let Some(libraries) = raw.libraries {
        for (alias, entry) in libraries {
            line_hint += 1;
            if let Some(dep) = library_to_dependency(
                &alias, &entry, &versions, path, line_hint,
            ) {
                out.push(dep);
            }
        }
    }

    if let Some(plugins) = raw.plugins {
        for (alias, entry) in plugins {
            line_hint += 1;
            if let Some(dep) = plugin_to_dependency(
                &alias, &entry, &versions, path, line_hint,
            ) {
                out.push(dep);
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Default, Deserialize)]
struct CatalogToml {
    #[serde(default)]
    versions: Option<HashMap<String, String>>,
    #[serde(default)]
    libraries: Option<HashMap<String, LibraryEntry>>,
    #[serde(default)]
    plugins: Option<HashMap<String, PluginEntry>>,
}

#[derive(Debug, Deserialize)]
struct LibraryEntry {
    module: Option<String>,
    group: Option<String>,
    name: Option<String>,
    version: Option<CatalogVersion>,
}

#[derive(Debug, Deserialize)]
struct PluginEntry {
    id: Option<String>,
    version: Option<CatalogVersion>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CatalogVersion {
    Plain(String),
    Ref { r#ref: String },
}

fn resolve_version(
    v: &CatalogVersion,
    versions: &HashMap<String, String>,
) -> String {
    match v {
        CatalogVersion::Plain(s) => s.clone(),
        CatalogVersion::Ref { r#ref } => {
            versions.get(r#ref).cloned().unwrap_or_default()
        }
    }
}

fn library_to_dependency(
    _alias: &str,
    entry: &LibraryEntry,
    versions: &HashMap<String, String>,
    path: &Path,
    line: u32,
) -> Option<ParsedDependency> {
    let (group, artifact, version) = if let Some(module) = &entry.module {
        let (g, a, v) = parse_gav_triple(module)?;
        let ver = if v.is_empty() {
            entry
                .version
                .as_ref()
                .map(|cv| resolve_version(cv, versions))
                .unwrap_or_default()
        } else {
            v
        };
        (g, a, ver)
    } else {
        let g = entry.group.clone()?;
        let a = entry.name.clone()?;
        let ver = entry
            .version
            .as_ref()
            .map(|cv| resolve_version(cv, versions))
            .unwrap_or_default();
        (g, a, ver)
    };
    Some(ParsedDependency {
        package: Package {
            name: maven_package_name(&group, &artifact),
            version,
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        },
        path: path.to_path_buf(),
        start_line: line,
        end_line: None,
        kind: DeclarationKind::Manifest,
    })
}

fn plugin_to_dependency(
    _alias: &str,
    entry: &PluginEntry,
    versions: &HashMap<String, String>,
    path: &Path,
    line: u32,
) -> Option<ParsedDependency> {
    let id = entry.id.as_ref()?;
    let ver = entry
        .version
        .as_ref()
        .map(|cv| resolve_version(cv, versions))
        .unwrap_or_default();
    let parts: Vec<&str> = id.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let artifact = parts.last()?.to_string();
    let group = parts[..parts.len() - 1].join(".");
    Some(ParsedDependency {
        package: Package {
            name: maven_package_name(&group, &artifact),
            version: ver,
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        },
        path: path.to_path_buf(),
        start_line: line,
        end_line: None,
        kind: DeclarationKind::Manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = r#"
[versions]
guava = "33.0.0-jre"

[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
junit = { group = "org.junit.jupiter", name = "junit-jupiter", version = "5.10.0" }

[plugins]
spring = { id = "org.springframework.boot", version = "3.2.0" }
"#;

    #[test]
    fn version_alias_resolution() {
        let pkgs = parse_version_catalog(CATALOG).unwrap();
        assert!(pkgs.iter().any(|p| {
            p.name == "com.google.guava:guava" && p.version == "33.0.0-jre"
        }));
        assert!(
            pkgs.iter()
                .any(|p| p.name == "org.junit.jupiter:junit-jupiter")
        );
    }
}
