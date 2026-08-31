// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse CycloneDX 1.x and SPDX 2.x / 3.0 JSON into packages (FR-038).

use async_trait::async_trait;
use std::path::Path;

use vlz_db::{Package, package_from_purl};
use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

use crate::names::SBOM_LANGUAGE_NAME;

/// Parse SBOM JSON bytes into packages (CycloneDX 1.x or SPDX 2.x / 3.0).
pub fn parse_sbom_bytes(bytes: &[u8]) -> Result<Vec<Package>, ParserError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| ParserError::Parse(format!("invalid SBOM JSON: {e}")))?;
    parse_sbom_json(&value)
}

/// Parse a JSON value as CycloneDX 1.x or SPDX 2.x / 3.0 inventory.
///
/// A recognized document with zero usable packages returns `Ok([])`
/// (`scanned_transitive` empty set per FR-038).
pub fn parse_sbom_json(
    value: &serde_json::Value,
) -> Result<Vec<Package>, ParserError> {
    if is_cyclonedx(value) {
        return Ok(parse_cyclonedx(value));
    }
    if is_spdx3(value) {
        return Ok(parse_spdx3(value));
    }
    if is_spdx2(value) {
        return Ok(parse_spdx2(value));
    }
    Err(ParserError::Parse(
        "unrecognized SBOM: expected CycloneDX (bomFormat) or SPDX 2.x/3.0 JSON"
            .to_string(),
    ))
}

fn is_cyclonedx(value: &serde_json::Value) -> bool {
    value
        .get("bomFormat")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("CycloneDX"))
}

fn is_spdx3(value: &serde_json::Value) -> bool {
    value
        .get("@type")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "SpdxDocument")
        || value.get("element").is_some()
            && value
                .get("@context")
                .and_then(|v| v.as_str())
                .is_some_and(|c| c.contains("spdx.org"))
}

fn is_spdx2(value: &serde_json::Value) -> bool {
    value
        .get("spdxVersion")
        .and_then(|v| v.as_str())
        .is_some_and(|s| {
            let upper = s.to_ascii_uppercase();
            upper.starts_with("SPDX-2.")
        })
}

fn parse_cyclonedx(value: &serde_json::Value) -> Vec<Package> {
    let Some(components) = value.get("components").and_then(|c| c.as_array())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for component in components {
        match package_from_component(component) {
            Some(pkg) => out.push(pkg),
            None => {
                let name = component
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("<unknown>");
                eprintln!(
                    "vlz warning: skipping SBOM component without usable purl/version: {name}"
                );
            }
        }
    }
    dedupe_packages(out)
}

fn package_from_component(component: &serde_json::Value) -> Option<Package> {
    if let Some(purl) = component.get("purl").and_then(|p| p.as_str())
        && let Some(pkg) = package_from_purl(purl)
    {
        return Some(pkg);
    }
    let name = component.get("name").and_then(|n| n.as_str())?;
    let version = component.get("version").and_then(|v| v.as_str())?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // Without purl we cannot map ecosystem reliably; skip (FR-038).
    None
}

fn parse_spdx3(value: &serde_json::Value) -> Vec<Package> {
    let Some(elements) = value.get("element").and_then(|e| e.as_array())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for element in elements {
        let ty = element.get("@type").and_then(|t| t.as_str()).unwrap_or("");
        if ty != "Package" {
            continue;
        }
        match package_from_spdx3_package(element) {
            Some(pkg) => out.push(pkg),
            None => {
                let name = element
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("<unknown>");
                eprintln!(
                    "vlz warning: skipping SPDX package without usable packageUrl/version: {name}"
                );
            }
        }
    }
    dedupe_packages(out)
}

fn package_from_spdx3_package(element: &serde_json::Value) -> Option<Package> {
    if let Some(purl) = element.get("packageUrl").and_then(|p| p.as_str()) {
        return package_from_purl(purl);
    }
    None
}

fn parse_spdx2(value: &serde_json::Value) -> Vec<Package> {
    let Some(packages) = value.get("packages").and_then(|p| p.as_array())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for package in packages {
        match package_from_spdx2_package(package) {
            Some(pkg) => out.push(pkg),
            None => {
                let name = package
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("<unknown>");
                eprintln!(
                    "vlz warning: skipping SPDX package without usable purl/version: {name}"
                );
            }
        }
    }
    dedupe_packages(out)
}

fn package_from_spdx2_package(package: &serde_json::Value) -> Option<Package> {
    let refs = package.get("externalRefs")?.as_array()?;
    for reference in refs {
        let ref_type = reference
            .get("referenceType")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if !ref_type.eq_ignore_ascii_case("purl") {
            continue;
        }
        let locator =
            reference.get("referenceLocator").and_then(|l| l.as_str())?;
        if let Some(pkg) = package_from_purl(locator) {
            return Some(pkg);
        }
    }
    None
}

fn dedupe_packages(mut packages: Vec<Package>) -> Vec<Package> {
    packages.sort_by(|a, b| {
        (
            a.ecosystem.as_deref().unwrap_or(""),
            a.name.as_str(),
            a.version.as_str(),
        )
            .cmp(&(
                b.ecosystem.as_deref().unwrap_or(""),
                b.name.as_str(),
                b.version.as_str(),
            ))
    });
    packages.dedup();
    packages
}

/// Parser for CycloneDX / SPDX JSON SBOM entry points.
#[derive(Debug, Default)]
pub struct SbomParser;

impl SbomParser {
    /// Create an SBOM parser.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Parser for SbomParser {
    fn language_name(&self) -> &'static str {
        SBOM_LANGUAGE_NAME
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let bytes =
            tokio::fs::read(manifest).await.map_err(ParserError::Io)?;
        let packages = parse_sbom_bytes(&bytes)?;
        Ok(DependencyGraph {
            packages,
            parsed_dependencies: Vec::new(),
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use vlz_db::{CRATES_IO_ECOSYSTEM, PYPI_ECOSYSTEM};

    #[test]
    fn parse_cyclonedx_1_6_with_purls() {
        let json = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0"
                },
                {
                    "type": "library",
                    "name": "serde",
                    "version": "1.0.0",
                    "purl": "pkg:cargo/serde@1.0.0"
                }
            ]
        });
        let pkgs = parse_sbom_json(&json).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| {
            p.name == "requests"
                && p.version == "2.31.0"
                && p.ecosystem.as_deref() == Some(PYPI_ECOSYSTEM)
        }));
        assert!(pkgs.iter().any(|p| {
            p.name == "serde"
                && p.ecosystem.as_deref() == Some(CRATES_IO_ECOSYSTEM)
        }));
    }

    #[test]
    fn parse_spdx3_with_package_url() {
        let json = serde_json::json!({
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@type": "SpdxDocument",
            "spdxId": "urn:spdx.dev:doc-test",
            "element": [
                {
                    "@type": "Package",
                    "spdxId": "urn:spdx.dev:pkg-pypi-requests-2-31-0",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "packageUrl": "pkg:pypi/requests@2.31.0"
                },
                {
                    "@type": "Vulnerability",
                    "spdxId": "urn:spdx.dev:vuln-CVE-1"
                }
            ]
        });
        let pkgs = parse_sbom_json(&json).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, "2.31.0");
    }

    #[test]
    fn rejects_unrecognized_json() {
        let err = parse_sbom_json(&serde_json::json!({"foo": 1})).unwrap_err();
        assert!(matches!(err, ParserError::Parse(_)));
    }

    #[test]
    fn empty_recognized_bom_yields_empty_package_set() {
        let empty_components = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": []
        });
        assert!(parse_sbom_json(&empty_components).unwrap().is_empty());

        let all_skipped = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                { "type": "library", "name": "x", "version": "1.0.0" }
            ]
        });
        assert!(parse_sbom_json(&all_skipped).unwrap().is_empty());
    }

    #[test]
    fn parse_cyclonedx_1_4_and_1_5() {
        for spec in ["1.4", "1.5"] {
            let json = serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": spec,
                "components": [{
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21"
                }]
            });
            let pkgs = parse_sbom_json(&json).unwrap();
            assert_eq!(pkgs.len(), 1, "specVersion {spec}");
            assert_eq!(pkgs[0].name, "lodash");
        }
    }

    #[test]
    fn parse_spdx_2_3_json_with_purl_external_ref() {
        let json = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "example",
            "documentNamespace": "https://example.com/spdx",
            "dataLicense": "CC0-1.0",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-requests",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.31.0"
                        }
                    ]
                },
                {
                    "SPDXID": "SPDXRef-Package-skip",
                    "name": "no-purl",
                    "versionInfo": "1.0.0",
                    "downloadLocation": "NOASSERTION"
                }
            ]
        });
        let pkgs = parse_sbom_json(&json).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, "2.31.0");
        assert_eq!(pkgs[0].ecosystem.as_deref(), Some(PYPI_ECOSYSTEM));
    }

    #[test]
    fn parse_spdx_2_2_json() {
        let json = serde_json::json!({
            "spdxVersion": "SPDX-2.2",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "example",
            "documentNamespace": "https://example.com/spdx22",
            "dataLicense": "CC0-1.0",
            "packages": [{
                "SPDXID": "SPDXRef-Package-serde",
                "name": "serde",
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:cargo/serde@1.0.0"
                }]
            }]
        });
        let pkgs = parse_sbom_json(&json).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].ecosystem.as_deref(), Some(CRATES_IO_ECOSYSTEM));
    }

    #[test]
    fn skips_component_without_purl() {
        let json = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                { "type": "library", "name": "x", "version": "1.0.0" },
                {
                    "type": "library",
                    "name": "y",
                    "version": "2.0.0",
                    "purl": "pkg:npm/y@2.0.0"
                }
            ]
        });
        let pkgs = parse_sbom_json(&json).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "y");
    }

    #[tokio::test]
    async fn parser_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bom.json");
        let body = br#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21"
            }]
        }"#;
        std::fs::File::create(&path)
            .unwrap()
            .write_all(body)
            .unwrap();
        let graph = SbomParser::new().parse(&path).await.unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.manifest_path.as_deref(), Some(path.as_path()));
    }
}
