// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse Gradle `verification-metadata.xml` resolved component pins (NFR-025).

use std::collections::HashSet;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use vlz_db::{DeclarationKind, MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use crate::coordinate::maven_package_name;

/// Basename of the Gradle dependency verification file.
pub const VERIFICATION_METADATA_NAME: &str = "verification-metadata.xml";

/// Maximum XML element nesting depth (defensive cap, SEC-017).
const MAX_DEPTH: u32 = 256;

/// True when `name` is the verification metadata basename.
pub fn is_verification_metadata(name: &str) -> bool {
    name == VERIFICATION_METADATA_NAME
}

/// Parse `verification-metadata.xml` content into packages.
pub fn parse_verification_metadata(
    content: &str,
) -> Result<Vec<Package>, ParserError> {
    Ok(parse_verification_metadata_with_declarations(
        content,
        Path::new(VERIFICATION_METADATA_NAME),
    )?
    .0)
}

/// Parse `verification-metadata.xml` with FR-036a declaration metadata.
///
/// Extracts `<component group name version>` entries as Maven pins. A
/// component is usable only when `group`, `name`, and `version` are all
/// present and non-empty (FR-022 usable-lock rule).
pub fn parse_verification_metadata_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let mut reader = Reader::from_reader(content.as_bytes());
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut packages = Vec::new();
    let mut parsed = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut depth: u32 = 0;

    loop {
        let event = reader.read_event_into(&mut buf).map_err(|e| {
            ParserError::Parse(format!(
                "verification-metadata parse error: {e}"
            ))
        })?;
        match event {
            Event::Start(ref e) => {
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(ParserError::Parse(
                        "verification-metadata nesting too deep".to_string(),
                    ));
                }
                handle_component(
                    e,
                    path,
                    content,
                    &reader,
                    &mut seen,
                    &mut packages,
                    &mut parsed,
                );
            }
            Event::Empty(ref e) => {
                handle_component(
                    e,
                    path,
                    content,
                    &reader,
                    &mut seen,
                    &mut packages,
                    &mut parsed,
                );
            }
            Event::End(_) => {
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok((packages, parsed))
}

/// Extract a `<component>` start/empty event into packages and declarations.
fn handle_component(
    e: &quick_xml::events::BytesStart<'_>,
    path: &Path,
    content: &str,
    reader: &quick_xml::Reader<&[u8]>,
    seen: &mut HashSet<String>,
    packages: &mut Vec<Package>,
    parsed: &mut Vec<ParsedDependency>,
) {
    if e.name().as_ref() != "component" {
        return;
    }
    let Some((group, artifact, version)) = extract_component_attrs(e) else {
        return;
    };
    let name = maven_package_name(&group, &artifact);
    let key = format!("{name}:{version}");
    if !seen.insert(key) {
        return;
    }
    let line = line_at_offset(content, reader.buffer_position() as usize);
    let pkg = Package {
        name: name.clone(),
        version: version.clone(),
        ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
    };
    packages.push(pkg.clone());
    parsed.push(ParsedDependency {
        package: pkg,
        path: path.to_path_buf(),
        start_line: line,
        end_line: None,
        kind: DeclarationKind::Lockfile,
    });
}

/// Extract `(group, artifact, version)` from a `<component>` start event.
fn extract_component_attrs(
    e: &quick_xml::events::BytesStart<'_>,
) -> Option<(String, String, String)> {
    let mut group = None;
    let mut name = None;
    let mut version = None;
    for attr in e.attributes().flatten() {
        let value = attr.value.to_string();
        match attr.key.as_ref() {
            "group" => group = Some(value),
            "name" => name = Some(value),
            "version" => version = Some(value),
            _ => {}
        }
    }
    let group = group.filter(|g| !g.is_empty())?;
    let name = name.filter(|n| !n.is_empty())?;
    let version = version.filter(|v| !v.is_empty())?;
    Some((group, name, version))
}

/// 1-based line number for `offset` within `content`.
fn line_at_offset(content: &str, offset: usize) -> u32 {
    let bytes = content.as_bytes();
    let end = offset.min(bytes.len());
    let count = bytes[..end].iter().filter(|&&b| b == b'\n').count();
    (count + 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verification_metadata_components() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata>
  <components>
    <component group="com.example" name="foo" version="1.0">
      <artifact name="foo.jar">
        <sha256 value="abc"/>
      </artifact>
    </component>
    <component group="org.junit" name="junit" version="5.10.0"/>
  </components>
</verification-metadata>"#;
        let packages = parse_verification_metadata(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "com.example:foo");
        assert_eq!(packages[0].version, "1.0");
        assert_eq!(packages[1].name, "org.junit:junit");
        assert_eq!(packages[1].version, "5.10.0");
    }

    #[test]
    fn parse_verification_metadata_skips_incomplete_components() {
        let content = r#"<verification-metadata>
  <components>
    <component group="com.example" name="foo"/>
    <component group="org.junit" name="junit" version="5.10.0"/>
  </components>
</verification-metadata>"#;
        let packages = parse_verification_metadata(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "org.junit:junit");
    }

    #[test]
    fn parse_verification_metadata_dedupes() {
        let content = r#"<verification-metadata>
  <components>
    <component group="com.example" name="foo" version="1.0"/>
    <component group="com.example" name="foo" version="1.0"/>
  </components>
</verification-metadata>"#;
        let packages = parse_verification_metadata(content).unwrap();
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn parse_verification_metadata_empty() {
        let content =
            "<verification-metadata><components/></verification-metadata>";
        let packages = parse_verification_metadata(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_verification_metadata_invalid_xml() {
        let content = "<verification-metadata><component";
        let err = parse_verification_metadata(content).unwrap_err();
        match &err {
            ParserError::Parse(s) => {
                assert!(s.contains("verification-metadata"))
            }
            _ => panic!("expected Parse error"),
        }
    }

    #[test]
    fn parse_verification_metadata_with_declarations_sets_kind() {
        let content = r#"<verification-metadata>
  <components>
    <component group="com.example" name="foo" version="1.0"/>
  </components>
</verification-metadata>"#;
        let (packages, parsed) =
            parse_verification_metadata_with_declarations(
                content,
                Path::new("verification-metadata.xml"),
            )
            .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, DeclarationKind::Lockfile);
    }

    #[test]
    fn is_verification_metadata_name() {
        assert!(is_verification_metadata("verification-metadata.xml"));
        assert!(!is_verification_metadata("gradle.lockfile"));
    }
}
