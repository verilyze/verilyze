// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse legacy NuGet `packages.config` manifests.

use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use vlz_db::{DeclarationKind, NUGET_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::packages_lock::is_nuget_package_name;

/// Parse `packages.config` into direct NuGet packages.
pub fn parse_packages_config(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_packages_config_with_declarations(
        content,
        Path::new("packages.config"),
    )?
    .0)
}

/// Parse with declaration metadata (FR-036a).
pub fn parse_packages_config_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut packages = Vec::new();
    let mut parsed = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if e.local_name().as_ref() != "package" {
                    continue;
                }
                let line = reader.error_position().saturating_add(1) as u32;
                let mut id = None;
                let mut version = String::new();
                for attr in e.attributes().flatten() {
                    let key = attr.key.local_name().as_ref().to_string();
                    let value = attr
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map(|v| v.into_owned())
                        .unwrap_or_default();
                    if key.eq_ignore_ascii_case("id") {
                        id = Some(value);
                    } else if key.eq_ignore_ascii_case("version") {
                        version = value;
                    }
                }
                if let Some(name) = id
                    && is_nuget_package_name(&name)
                    && !version.is_empty()
                {
                    let pkg = Package {
                        name,
                        version,
                        ecosystem: Some(NUGET_ECOSYSTEM.to_string()),
                    };
                    packages.push(pkg.clone());
                    parsed.push(ParsedDependency {
                        package: pkg,
                        path: path.to_path_buf(),
                        start_line: if line == 0 { 1 } else { line },
                        end_line: None,
                        kind: DeclarationKind::Manifest,
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "packages.config parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok((packages, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="NotValid" version="" />
</packages>"#;

    #[test]
    fn parse_packages_config_entries() {
        let packages = parse_packages_config(SAMPLE).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Newtonsoft.Json");
        assert_eq!(packages[0].version, "13.0.3");
    }
}
