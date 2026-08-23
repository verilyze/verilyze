// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse Maven `pom.xml` with [`quick-xml`] (NFR-025: XML is incompatible with
//! TOML/JSON; hand-rolled XML is impractical; quick-xml does not enable DTD/XXE).

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use vlz_db::{DeclarationKind, MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use crate::coordinate::{maven_package_name, resolve_maven_property};

/// Maximum `pom.xml` size (1 MiB, SEC-017).
pub const POM_MAX_BYTES: usize = 1024 * 1024;

/// Maximum XML element nesting depth.
pub const POM_MAX_DEPTH: u32 = 256;

type ProjectCoords = (Option<String>, Option<String>, Option<String>);

fn text_content(text: &quick_xml::events::BytesText<'_>) -> String {
    text.decode().map(Cow::into_owned).unwrap_or_default()
}

fn append_general_ref(
    buf: &mut String,
    reference: &quick_xml::events::BytesRef<'_>,
) {
    let name = std::str::from_utf8(reference.as_ref()).unwrap_or("");
    match name {
        "amp" => buf.push('&'),
        "lt" => buf.push('<'),
        "gt" => buf.push('>'),
        "quot" => buf.push('"'),
        "apos" => buf.push('\''),
        _ if name.starts_with("#x") || name.starts_with("#X") => {
            if let Ok(code) = u32::from_str_radix(&name[2..], 16)
                && let Some(ch) = char::from_u32(code)
            {
                buf.push(ch);
            }
        }
        _ if name.starts_with('#') => {
            if let Ok(code) = name[1..].parse::<u32>()
                && let Some(ch) = char::from_u32(code)
            {
                buf.push(ch);
            }
        }
        _ => {}
    }
}

fn assign_dependency_field(dep: &mut RawDependency, field: &str, value: &str) {
    match field {
        "groupId" => dep.group_id = value.to_string(),
        "artifactId" => dep.artifact_id = value.to_string(),
        "version" => dep.version = value.to_string(),
        "scope" => dep.scope = value.to_string(),
        "type" => dep.dep_type = value.to_string(),
        _ => {}
    }
}

#[derive(Debug, Default, Clone)]
struct RawDependency {
    group_id: String,
    artifact_id: String,
    version: String,
    scope: String,
    dep_type: String,
    line: u32,
}

/// Parse `pom.xml` into packages (direct dependencies with resolved versions only).
pub fn parse_pom_xml(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(
        parse_pom_xml_with_declarations(content, Path::new("pom.xml"))?
            .into_iter()
            .filter(|d| !d.package.version.is_empty())
            .map(|d| d.package)
            .collect(),
    )
}

/// Parse with declaration metadata; versionless deps kept for FR-036a.
pub fn parse_pom_xml_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    check_pom_limits(content)?;
    let props = parse_properties(content)?;
    let (project_group, project_artifact, project_version) =
        parse_project_coords(content, &props)?;
    let raw = parse_dependencies_block(content)?;
    let mut out = Vec::new();
    for dep in raw {
        if should_skip_dependency(&dep) {
            continue;
        }
        let group = resolve_maven_property(
            &dep.group_id,
            &props,
            project_group.as_deref(),
            project_artifact.as_deref(),
            project_version.as_deref(),
        );
        let artifact = resolve_maven_property(
            &dep.artifact_id,
            &props,
            project_group.as_deref(),
            project_artifact.as_deref(),
            project_version.as_deref(),
        );
        let version = resolve_maven_property(
            &dep.version,
            &props,
            project_group.as_deref(),
            project_artifact.as_deref(),
            project_version.as_deref(),
        );
        if group.is_empty() || artifact.is_empty() {
            continue;
        }
        let name = maven_package_name(&group, &artifact);
        out.push(ParsedDependency {
            package: Package {
                name,
                version,
                ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
            },
            path: path.to_path_buf(),
            start_line: dep.line,
            end_line: None,
            kind: DeclarationKind::Manifest,
        });
    }
    Ok(out)
}

fn check_pom_limits(content: &str) -> Result<(), ParserError> {
    if content.len() > POM_MAX_BYTES {
        return Err(ParserError::Parse(format!(
            "pom.xml exceeds maximum size of {POM_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn should_skip_dependency(dep: &RawDependency) -> bool {
    dep.scope.eq_ignore_ascii_case("system")
        || dep.scope.eq_ignore_ascii_case("import")
        || (dep.dep_type.eq_ignore_ascii_case("pom")
            && dep.scope.eq_ignore_ascii_case("import"))
}

fn line_number_at(content: &str, byte_offset: usize) -> u32 {
    let end = byte_offset.min(content.len());
    content.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

fn parse_properties(
    content: &str,
) -> Result<HashMap<String, String>, ParserError> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut props = HashMap::new();
    let mut buf = Vec::new();
    let mut in_properties = false;
    let mut current_key: Option<String> = None;
    let mut depth: u32 = 0;

    loop {
        let event = reader.read_event_into(&mut buf);
        let offset = reader.buffer_position();
        match event {
            Ok(Event::Start(e)) => {
                depth += 1;
                if depth > POM_MAX_DEPTH {
                    return Err(ParserError::Parse(
                        "pom.xml exceeds maximum nesting depth".into(),
                    ));
                }
                let name = String::from_utf8_lossy(e.local_name().as_ref())
                    .into_owned();
                if name == "properties" {
                    in_properties = true;
                } else if in_properties {
                    current_key = Some(name);
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(key) = current_key.take() {
                    let val = text_content(&e);
                    if !val.is_empty() {
                        props.insert(key, val);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if name == "properties" {
                    in_properties = false;
                }
                depth = depth.saturating_sub(1);
                let _ = offset;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "pom.xml parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(props)
}

fn parse_project_coords(
    content: &str,
    props: &HashMap<String, String>,
) -> Result<ProjectCoords, ParserError> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_project = false;
    let mut current: Option<String> = None;
    let mut group = None;
    let mut artifact = None;
    let mut version = None;
    let mut depth: u32 = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                depth += 1;
                if depth > POM_MAX_DEPTH {
                    return Err(ParserError::Parse(
                        "pom.xml exceeds maximum nesting depth".into(),
                    ));
                }
                let name = String::from_utf8_lossy(e.local_name().as_ref())
                    .into_owned();
                if name == "project" {
                    in_project = true;
                } else if in_project && depth <= 3 {
                    current = Some(name);
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(key) = current.take() {
                    let val = text_content(&e);
                    match key.as_str() {
                        "groupId" if group.is_none() => group = Some(val),
                        "artifactId" if artifact.is_none() => {
                            artifact = Some(val)
                        }
                        "version" if version.is_none() => version = Some(val),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"project" {
                    in_project = false;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "pom.xml parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }
    let project_group =
        group.map(|g| resolve_maven_property(&g, props, None, None, None));
    let project_artifact = artifact.map(|a| {
        resolve_maven_property(&a, props, project_group.as_deref(), None, None)
    });
    let project_version = version.map(|v| {
        resolve_maven_property(
            &v,
            props,
            project_group.as_deref(),
            project_artifact.as_deref(),
            None,
        )
    });
    Ok((project_group, project_artifact, project_version))
}

fn parse_dependencies_block(
    content: &str,
) -> Result<Vec<RawDependency>, ParserError> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut deps = Vec::new();
    let mut in_dependency_management = false;
    let mut in_dependencies = false;
    let mut in_dependency = false;
    let mut current_field: Option<String> = None;
    let mut field_buf = String::new();
    let mut current = RawDependency::default();
    let mut depth: u32 = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                depth += 1;
                if depth > POM_MAX_DEPTH {
                    return Err(ParserError::Parse(
                        "pom.xml exceeds maximum nesting depth".into(),
                    ));
                }
                let name = String::from_utf8_lossy(e.local_name().as_ref())
                    .into_owned();
                if name == "dependencyManagement" {
                    in_dependency_management = true;
                } else if name == "dependencies" && !in_dependency_management {
                    in_dependencies = true;
                } else if in_dependencies && name == "dependency" {
                    in_dependency = true;
                    current = RawDependency::default();
                    current.line = line_number_at(
                        content,
                        reader.buffer_position() as usize,
                    );
                } else if in_dependency {
                    current_field = Some(name);
                    field_buf.clear();
                }
            }
            Ok(Event::Text(e)) => {
                if current_field.is_some() {
                    field_buf.push_str(&text_content(&e));
                }
            }
            Ok(Event::GeneralRef(e)) => {
                if current_field.is_some() {
                    append_general_ref(&mut field_buf, &e);
                }
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if in_dependency
                    && let Some(field) = current_field.as_ref()
                    && name == field.as_str()
                {
                    assign_dependency_field(&mut current, field, &field_buf);
                    current_field = None;
                    field_buf.clear();
                }
                if name == "dependency" && in_dependency {
                    deps.push(current.clone());
                    in_dependency = false;
                } else if name == "dependencies" {
                    in_dependencies = false;
                } else if name == "dependencyManagement" {
                    in_dependency_management = false;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "pom.xml parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <junit.version>5.10.0</junit.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>${junit.version}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
"#;

    #[test]
    fn resolves_same_file_properties() {
        let deps = parse_pom_xml(SIMPLE).unwrap();
        assert!(deps.iter().any(|p| {
            p.name == "org.junit.jupiter:junit-jupiter"
                && p.version == "5.10.0"
        }));
    }

    #[test]
    fn skips_bom_import() {
        let pom = r#"<project><dependencies>
      <dependency><groupId>org.springframework</groupId><artifactId>spring-boot-dependencies</artifactId><version>3.0.0</version><type>pom</type><scope>import</scope></dependency>
    </dependencies></project>"#;
        assert!(parse_pom_xml(pom).unwrap().is_empty());
    }

    #[test]
    fn skips_dependency_management_entries() {
        let pom = r#"<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.managed</groupId>
        <artifactId>lib</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.direct</groupId>
      <artifactId>app</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let deps = parse_pom_xml(pom).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.direct:app");
    }

    #[test]
    fn decodes_xml_entities_in_version() {
        let pom = r#"<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1&amp;2</version></dependency>
    </dependencies></project>"#;
        assert_eq!(parse_pom_xml(pom).unwrap()[0].version, "1&2");
    }

    #[test]
    fn decodes_numeric_entity_in_version() {
        let pom = r#"<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1&#50;</version></dependency>
    </dependencies></project>"#;
        assert_eq!(parse_pom_xml(pom).unwrap()[0].version, "12");
    }

    #[test]
    fn rejects_oversized_pom() {
        let huge = " ".repeat(POM_MAX_BYTES + 1);
        assert!(parse_pom_xml(&huge).is_err());
    }

    #[test]
    fn skips_system_scope_dependency() {
        let pom = r#"<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version><scope>system</scope></dependency>
    </dependencies></project>"#;
        assert!(parse_pom_xml(pom).unwrap().is_empty());
    }

    #[test]
    fn classifier_not_in_osv_name() {
        let pom = r#"<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version><classifier>tests</classifier></dependency>
    </dependencies></project>"#;
        assert_eq!(parse_pom_xml(pom).unwrap()[0].name, "g:a");
    }

    #[test]
    fn junit_dependency_start_line_in_simple_pom() {
        let deps =
            parse_pom_xml_with_declarations(SIMPLE, Path::new("pom.xml"))
                .unwrap();
        let junit = deps
            .iter()
            .find(|d| d.package.name == "org.junit.jupiter:junit-jupiter")
            .expect("junit dependency");
        assert_eq!(junit.start_line, 10);
    }

    #[test]
    fn line_number_at_handles_non_char_boundary_offset() {
        let content = "abc\u{feff}def\nghi";
        // Byte 4 is inside the 3-byte BOM (bytes 3..6); must not panic.
        assert_eq!(line_number_at(content, 4), 1);
    }

    #[test]
    fn parses_pom_with_bom_before_dependency() {
        let pom = "<project><dependencies>\u{feff}<dependency>\
             <groupId>g</groupId><artifactId>a</artifactId>\
             <version>1.0</version></dependency></dependencies></project>";
        let deps = parse_pom_xml(pom).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "g:a");
        assert_eq!(deps[0].version, "1.0");
    }

    #[test]
    fn dependency_start_line_with_crlf() {
        let lf = "<project>\n\
                  <dependencies>\n\
                  <dependency>\n\
                  <groupId>g</groupId>\n\
                  <artifactId>a</artifactId>\n\
                  <version>1.0</version>\n\
                  </dependency>\n\
                  </dependencies>\n\
                  </project>\n";
        let crlf = lf.replace('\n', "\r\n");
        let path = Path::new("pom.xml");
        let lf_deps = parse_pom_xml_with_declarations(lf, path).unwrap();
        let crlf_deps = parse_pom_xml_with_declarations(&crlf, path).unwrap();
        assert_eq!(lf_deps.len(), 1);
        assert_eq!(crlf_deps.len(), 1);
        assert_eq!(crlf_deps[0].package.name, "g:a");
        assert_eq!(
            crlf_deps[0].start_line, lf_deps[0].start_line,
            "CRLF must yield the same start_line as LF"
        );
    }
}
