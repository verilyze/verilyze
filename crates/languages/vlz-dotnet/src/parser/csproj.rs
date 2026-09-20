// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse SDK-style `*.csproj` / `*.fsproj` / `*.vbproj` PackageReference
//! elements with [`quick-xml`] (NFR-025: XML is incompatible with TOML/JSON;
//! quick-xml does not enable DTD/XXE).

use std::collections::BTreeMap;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use vlz_db::{DeclarationKind, NUGET_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::packages_lock::is_nuget_package_name;

/// Maximum accepted size for a project file (1 MiB, SEC-017).
pub const DOTNET_MANIFEST_MAX_BYTES: u64 = 1024 * 1024;

/// Maximum XML element nesting depth.
pub const DOTNET_MANIFEST_MAX_DEPTH: u32 = 256;

/// Parse project file content into direct PackageReference dependencies.
pub fn parse_csproj(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_csproj_with_declarations(content, Path::new("App.csproj"))?.0)
}

/// Parse with declaration line metadata (FR-036a).
pub fn parse_csproj_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    if content.len() as u64 > DOTNET_MANIFEST_MAX_BYTES {
        return Err(ParserError::Parse(format!(
            ".NET project file exceeds {DOTNET_MANIFEST_MAX_BYTES} byte limit"
        )));
    }

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut depth = 0_u32;
    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                depth = depth.saturating_add(1);
                if depth > DOTNET_MANIFEST_MAX_DEPTH {
                    return Err(ParserError::Parse(
                        ".NET project file exceeds max XML depth".into(),
                    ));
                }
                let local = e.local_name().as_ref().to_string();
                if local.eq_ignore_ascii_case("PackageReference") {
                    let line =
                        reader.error_position().saturating_add(1) as u32;
                    let mut include = None;
                    let mut version = String::new();
                    for attr in e.attributes().flatten() {
                        let key = attr.key.local_name().as_ref().to_string();
                        let value = attr
                            .normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                            )
                            .map(|v| v.into_owned())
                            .unwrap_or_default();
                        if key.eq_ignore_ascii_case("Include")
                            || key.eq_ignore_ascii_case("Update")
                        {
                            include = Some(value);
                        } else if key.eq_ignore_ascii_case("Version") {
                            version = value;
                        }
                    }
                    if let Some(name) = include
                        && is_nuget_package_name(&name)
                        && !is_non_registry_version(&version)
                        && seen.insert(name.clone())
                    {
                        packages.push(ParsedDependency {
                            package: Package {
                                name,
                                // Ranges / CPM empties are not OSV-ready;
                                // resolver prefers packages.lock.json pins.
                                version,
                                ecosystem: Some(NUGET_ECOSYSTEM.to_string()),
                            },
                            path: path.to_path_buf(),
                            start_line: if line == 0 { 1 } else { line },
                            end_line: None,
                            kind: DeclarationKind::Manifest,
                        });
                    }
                }
                // Skip ProjectReference (not NuGet).
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    ".NET project file parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    // Prefer attribute-based line map when quick-xml line is coarse.
    let line_map = package_reference_lines(content);
    for dep in &mut packages {
        if let Some(line) = line_map.get(dep.package.name.as_str()) {
            dep.start_line = *line;
        }
    }

    let pkgs = packages.iter().map(|p| p.package.clone()).collect();
    Ok((pkgs, packages))
}

fn is_non_registry_version(spec: &str) -> bool {
    let lower = spec.trim().to_ascii_lowercase();
    lower.starts_with("file:")
        || lower.starts_with("path:")
        || lower.starts_with("project:")
}

fn package_reference_lines(content: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let re = regex::Regex::new(
        r#"(?i)<PackageReference\b[^>]*(?:Include|Update)\s*=\s*"([^"]+)""#,
    )
    .expect("valid PackageReference regex");
    for (i, line) in content.lines().enumerate() {
        if let Some(captures) = re.captures(line)
            && let Some(name) = captures.get(1)
            && is_nuget_package_name(name.as_str())
        {
            out.entry(name.as_str().to_string())
                .or_insert((i + 1) as u32);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_references() {
        let content = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
    <ProjectReference Include="..\Lib\Lib.csproj" />
  </ItemGroup>
</Project>
"#;
        let packages = parse_csproj(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "Newtonsoft.Json"));
        assert!(packages.iter().any(|p| p.name == "Serilog"));
        assert!(
            packages
                .iter()
                .all(|p| p.ecosystem.as_deref() == Some(NUGET_ECOSYSTEM))
        );
    }

    #[test]
    fn central_package_management_empty_version_kept() {
        let content = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Cli.Contract" />
  </ItemGroup>
</Project>
"#;
        let packages = parse_csproj(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Cli.Contract");
        assert_eq!(packages[0].version, "");
    }

    #[test]
    fn declarations_include_line_numbers() {
        let content = "<Project>\n  <PackageReference Include=\"A.B\" Version=\"1.0\" />\n</Project>\n";
        let (_, parsed) =
            parse_csproj_with_declarations(content, Path::new("App.csproj"))
                .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].start_line, 2);
    }

    #[test]
    fn invalid_xml_returns_parse_error() {
        assert!(parse_csproj("<Project><PackageReference").is_err());
    }

    #[test]
    fn skips_file_path_versions() {
        let content = r#"<Project>
  <PackageReference Include="Local.Pkg" Version="path:../local" />
  <PackageReference Include="Ok.Pkg" Version="1.0.0" />
</Project>
"#;
        let packages = parse_csproj(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Ok.Pkg");
    }
}
