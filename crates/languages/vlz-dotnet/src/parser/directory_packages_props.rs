// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse `Directory.Packages.props` central package management versions.

use std::collections::BTreeMap;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use vlz_db::Package;
use vlz_manifest_parser::{DependencyGraph, ParsedDependency, ParserError};

use super::packages_lock::is_nuget_package_name;

pub const DIRECTORY_PACKAGES_PROPS: &str = "Directory.Packages.props";

/// Parse `PackageVersion` entries from `Directory.Packages.props` content.
pub fn parse_directory_packages_props(
    content: &str,
) -> Result<BTreeMap<String, String>, ParserError> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut versions = BTreeMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if !e
                    .local_name()
                    .as_ref()
                    .eq_ignore_ascii_case("PackageVersion")
                {
                    continue;
                }
                let mut include = None;
                let mut version = String::new();
                for attr in e.attributes().flatten() {
                    let key = attr.key.local_name().as_ref().to_string();
                    let value = attr
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map(|v| v.into_owned())
                        .unwrap_or_default();
                    if key.eq_ignore_ascii_case("Include") {
                        include = Some(value);
                    } else if key.eq_ignore_ascii_case("Version") {
                        version = value;
                    }
                }
                if let Some(name) = include
                    && is_nuget_package_name(&name)
                    && !version.is_empty()
                {
                    versions.insert(name, version);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "Directory.Packages.props parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(versions)
}

fn is_project_manifest_path(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        n.ends_with(".csproj")
            || n.ends_with(".fsproj")
            || n.ends_with(".vbproj")
    })
}

fn project_dir_for(start: &Path) -> std::path::PathBuf {
    if start.is_file() || is_project_manifest_path(start) {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    }
}

fn merge_props_in_dir(merged: &mut BTreeMap<String, String>, dir: &Path) {
    let props = dir.join(DIRECTORY_PACKAGES_PROPS);
    if props.is_file()
        && let Ok(content) = std::fs::read_to_string(&props)
        && let Ok(local) = parse_directory_packages_props(&content)
    {
        merged.extend(local);
    }
}

/// Walk parents from `start` up to `scan_root` and merge CPM versions.
///
/// When `scan_root` is `None`, only the project directory adjacent to `start`
/// is checked (no parent walk).
pub fn load_central_package_versions(
    start: &Path,
    scan_root: Option<&Path>,
) -> BTreeMap<String, String> {
    let mut dir = project_dir_for(start);
    let mut merged = BTreeMap::new();
    if scan_root.is_none() {
        merge_props_in_dir(&mut merged, &dir);
        return merged;
    }
    let scan_root = scan_root.expect("scan_root branch handled above");
    let mut chain = Vec::new();
    loop {
        if !dir.starts_with(scan_root) {
            break;
        }
        chain.push(dir.clone());
        if dir == scan_root || !dir.pop() {
            break;
        }
    }
    for dir in chain.iter().rev() {
        merge_props_in_dir(&mut merged, dir);
    }
    merged
}

fn fill_packages_with_cpm(
    packages: &mut [Package],
    cpm: &BTreeMap<String, String>,
) {
    for pkg in packages.iter_mut() {
        if pkg.version.is_empty()
            && let Some(version) = cpm.get(&pkg.name)
        {
            pkg.version.clone_from(version);
        }
    }
}

fn fill_parsed_with_cpm(
    parsed: &mut [ParsedDependency],
    cpm: &BTreeMap<String, String>,
) {
    for dep in parsed.iter_mut() {
        if dep.package.version.is_empty()
            && let Some(version) = cpm.get(&dep.package.name)
        {
            dep.package.version.clone_from(version);
        }
    }
}

/// Return a copy of `graph` with empty package versions filled from CPM.
pub fn graph_with_central_package_versions(
    graph: &DependencyGraph,
    scan_root: Option<&Path>,
) -> DependencyGraph {
    let Some(manifest) = graph.manifest_path.as_deref() else {
        return graph.clone();
    };
    let cpm = load_central_package_versions(manifest, scan_root);
    if cpm.is_empty() {
        return graph.clone();
    }
    let mut packages = graph.packages.clone();
    let mut parsed_dependencies = graph.parsed_dependencies.clone();
    fill_packages_with_cpm(&mut packages, &cpm);
    fill_parsed_with_cpm(&mut parsed_dependencies, &cpm);
    DependencyGraph {
        packages,
        parsed_dependencies,
        manifest_path: graph.manifest_path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_versions() {
        let content = r#"<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>"#;
        let versions = parse_directory_packages_props(content).unwrap();
        assert_eq!(versions.get("Newtonsoft.Json").unwrap(), "13.0.3");
    }

    #[test]
    fn parent_walk_merges_cpm_versions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let nested = root.join("src/App");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            root.join(DIRECTORY_PACKAGES_PROPS),
            r#"<Project><ItemGroup>
  <PackageVersion Include="A" Version="1.0" />
</ItemGroup></Project>"#,
        )
        .unwrap();
        std::fs::write(
            nested.join(DIRECTORY_PACKAGES_PROPS),
            r#"<Project><ItemGroup>
  <PackageVersion Include="B" Version="2.0" />
</ItemGroup></Project>"#,
        )
        .unwrap();
        let merged = load_central_package_versions(
            &nested.join("App.csproj"),
            Some(root),
        );
        assert_eq!(merged.get("A").unwrap(), "1.0");
        assert_eq!(merged.get("B").unwrap(), "2.0");
    }

    #[test]
    fn without_scan_root_uses_only_project_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let nested = root.join("src/App");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            root.join(DIRECTORY_PACKAGES_PROPS),
            r#"<Project><ItemGroup>
  <PackageVersion Include="A" Version="1.0" />
</ItemGroup></Project>"#,
        )
        .unwrap();
        let merged =
            load_central_package_versions(&nested.join("App.csproj"), None);
        assert!(!merged.contains_key("A"));
    }

    #[test]
    fn graph_with_cpm_stops_at_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path();
        let scan = outside.join("scan");
        let nested = scan.join("proj");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            outside.join(DIRECTORY_PACKAGES_PROPS),
            r#"<Project><ItemGroup>
  <PackageVersion Include="Outside.Pkg" Version="9.9.9" />
</ItemGroup></Project>"#,
        )
        .unwrap();
        std::fs::write(
            scan.join(DIRECTORY_PACKAGES_PROPS),
            r#"<Project><ItemGroup>
  <PackageVersion Include="Scoped.Pkg" Version="1.0.0" />
</ItemGroup></Project>"#,
        )
        .unwrap();
        let graph = DependencyGraph {
            packages: vec![
                Package {
                    name: "Scoped.Pkg".into(),
                    version: String::new(),
                    ecosystem: Some("NuGet".into()),
                },
                Package {
                    name: "Outside.Pkg".into(),
                    version: String::new(),
                    ecosystem: Some("NuGet".into()),
                },
            ],
            parsed_dependencies: Vec::new(),
            manifest_path: Some(nested.join("App.csproj")),
        };
        let filled = graph_with_central_package_versions(&graph, Some(&scan));
        assert_eq!(filled.packages[0].version, "1.0.0");
        assert!(filled.packages[1].version.is_empty());
    }
}
