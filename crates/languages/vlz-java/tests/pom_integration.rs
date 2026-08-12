// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_java::{JavaManifestParser, parse_pom_xml};
use vlz_manifest_parser::Parser;

const PROPERTIES_POM: &str = r#"<?xml version="1.0"?>
<project>
  <properties><guava.version>33.0.0-jre</guava.version></properties>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
  </dependencies>
</project>
"#;

#[test]
fn property_resolution_integration() {
    let pkgs = parse_pom_xml(PROPERTIES_POM).unwrap();
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0].name, "com.google.guava:guava");
    assert_eq!(pkgs[0].version, "33.0.0-jre");
}

#[test]
fn bom_import_not_in_query_set() {
    let pom = r#"<project><dependencies>
      <dependency><groupId>org.springframework</groupId><artifactId>spring-boot-dependencies</artifactId><version>3.0.0</version><type>pom</type><scope>import</scope></dependency>
      <dependency><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></dependency>
    </dependencies></project>"#;
    let pkgs = parse_pom_xml(pom).unwrap();
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0].name, "com.example:app");
}

#[test]
fn dependency_management_not_in_query_set() {
    let pom = r#"<project>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>com.managed</groupId><artifactId>lib</artifactId><version>9.9.9</version></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></dependency>
  </dependencies>
</project>"#;
    let pkgs = parse_pom_xml(pom).unwrap();
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0].name, "com.example:app");
}

#[test]
fn xml_entity_in_version_integration() {
    let pom = r#"<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1&amp;2</version></dependency>
    </dependencies></project>"#;
    assert_eq!(parse_pom_xml(pom).unwrap()[0].version, "1&2");
}

#[tokio::test]
async fn parser_emits_versionless_for_fr036a() {
    let dir = tempfile::tempdir().unwrap();
    let pom = dir.path().join("pom.xml");
    std::fs::write(
        &pom,
        r#"<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId></dependency></dependencies></project>"#,
    )
    .unwrap();
    let graph = JavaManifestParser::new().parse(&pom).await.unwrap();
    assert!(graph.packages.is_empty());
    assert_eq!(graph.parsed_dependencies.len(), 1);
    assert!(graph.parsed_dependencies[0].package.version.is_empty());
}
