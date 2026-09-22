// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse `Directory.Packages.props` central package management versions.

use std::collections::BTreeMap;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use vlz_manifest_parser::ParserError;

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

/// Walk parents from `start` up to `scan_root` and merge CPM versions.
pub fn load_central_package_versions(
    start: &Path,
    scan_root: Option<&Path>,
) -> BTreeMap<String, String> {
    let mut dir = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };
    let mut chain = Vec::new();
    loop {
        if scan_root.is_some_and(|root| !dir.starts_with(root)) {
            break;
        }
        chain.push(dir.clone());
        if scan_root.is_some_and(|root| dir == root) || !dir.pop() {
            break;
        }
    }
    let mut merged = BTreeMap::new();
    for dir in chain.iter().rev() {
        let props = dir.join(DIRECTORY_PACKAGES_PROPS);
        if props.is_file()
            && let Ok(content) = std::fs::read_to_string(&props)
            && let Ok(local) = parse_directory_packages_props(&content)
        {
            merged.extend(local);
        }
    }
    merged
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
}
