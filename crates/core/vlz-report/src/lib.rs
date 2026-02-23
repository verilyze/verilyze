// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;
use serde::Serialize;
use std::io::Write;
use vlz_db::{CveRecord, CvssVersion, Package, Severity};

const DESCRIPTION_MAX_LEN: usize = 60;

/// Thresholds for mapping a CVSS score to a severity label (FR-013). Defaults per version.
#[derive(Debug, Clone)]
pub struct SeverityThresholds {
    pub critical_min: f32,
    pub high_min: f32,
    pub medium_min: f32,
    pub low_min: f32,
}

impl Default for SeverityThresholds {
    fn default() -> Self {
        Self {
            critical_min: 9.0,
            high_min: 7.0,
            medium_min: 4.0,
            low_min: 0.1,
        }
    }
}

/// Severity mapping configuration: default thresholds per CVSS version (FR-013).
#[derive(Debug, Clone, Default)]
pub struct SeverityConfig {
    pub v2: SeverityThresholds,
    pub v3: SeverityThresholds,
    pub v4: SeverityThresholds,
}

/// Resolve severity from primary CVSS score and version using the given config.
/// Returns Unknown if score or version is missing.
pub fn resolve_severity(
    score: Option<f32>,
    version: Option<CvssVersion>,
    config: &SeverityConfig,
) -> Severity {
    let Some(s) = score else {
        return Severity::Unknown;
    };
    let thresholds = match version {
        Some(CvssVersion::V2) => &config.v2,
        Some(CvssVersion::V3) => &config.v3,
        Some(CvssVersion::V4) => &config.v4,
        None => return Severity::Unknown,
    };
    if s >= thresholds.critical_min {
        Severity::Critical
    } else if s >= thresholds.high_min {
        Severity::High
    } else if s >= thresholds.medium_min {
        Severity::Medium
    } else if s >= thresholds.low_min {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error; source preserved for verbose mode (NFR-018).
    #[error("Serialization error")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

/// Simple data structure handed to the reporter. Each CVE has a pre-resolved severity (FR-013).
pub struct ReportData {
    pub findings: Vec<(Package, Vec<(CveRecord, Severity)>)>,
    /// All resolved packages (for SBOM formats). When Some, SBOM reporters list all components.
    pub all_packages: Option<Vec<Package>>,
}

#[async_trait]
pub trait Reporter: Send + Sync {
    /// Render the report to the given writer (used for stdout and --summary-file).
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError>;

    /// Render the report to stdout.
    async fn render(&self, data: &ReportData) -> Result<(), ReportError> {
        let mut buf = Vec::new();
        self.render_to_writer(data, &mut buf).await?;
        std::io::stdout().lock().write_all(&buf)?;
        Ok(())
    }

    /// Render the report to a file (FR-008 --summary-file).
    async fn render_to_path(
        &self,
        data: &ReportData,
        path: &std::path::Path,
    ) -> Result<(), ReportError> {
        let mut f = std::fs::File::create(path)?;
        self.render_to_writer(data, &mut f).await
    }
}

/// Default reporter that prints a plain-text table to stdout (FR-007).
#[derive(Debug, Default)]
pub struct DefaultReporter;

impl DefaultReporter {
    /// Create a new default reporter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for DefaultReporter {
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError> {
        if data.findings.is_empty() {
            writeln!(w, "No vulnerabilities found.")?;
            return Ok(());
        }
        writeln!(w, "Package | Version | CVE ID | Severity | Description")?;
        writeln!(w, "{}", "-".repeat(80))?;
        for (pkg, recs) in &data.findings {
            for (cve, severity) in recs {
                let severity_display = severity.as_str();
                let mut chars = cve.description.chars();
                let truncated: String =
                    chars.by_ref().take(DESCRIPTION_MAX_LEN).collect();
                let had_more = chars.next().is_some();
                let desc = truncated.trim().replace('\n', " ");
                let desc_display = if had_more {
                    format!("{}...", desc)
                } else {
                    desc
                };
                writeln!(
                    w,
                    "{} | {} | {} | {} | {}",
                    pkg.name,
                    pkg.version,
                    cve.id,
                    severity_display,
                    desc_display
                )?;
            }
        }
        w.flush()?;
        Ok(())
    }
}

/// JSON report shape: findings array of { package, cves } with severity per CVE.
#[derive(Serialize)]
struct JsonReport<'a> {
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    package: &'a Package,
    cves: Vec<JsonCveWithSeverity<'a>>,
}

#[derive(Serialize)]
struct JsonCveWithSeverity<'a> {
    #[serde(flatten)]
    cve: &'a CveRecord,
    severity: String,
}

/// Reporter that outputs findings as JSON to stdout (FR-007 --format json).
#[derive(Debug, Default)]
pub struct JsonReporter;

impl JsonReporter {
    /// Create a new JSON reporter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for JsonReporter {
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError> {
        let report = JsonReport {
            findings: data
                .findings
                .iter()
                .map(|(package, recs)| JsonFinding {
                    package,
                    cves: recs
                        .iter()
                        .map(|(cve, severity)| JsonCveWithSeverity {
                            cve,
                            severity: severity.as_str().to_string(),
                        })
                        .collect(),
                })
                .collect(),
        };
        let s = serde_json::to_string_pretty(&report)?;
        writeln!(w, "{}", s).map_err(ReportError::Io)?;
        w.flush()?;
        Ok(())
    }
}

/// Reporter that outputs a minimal HTML table (FR-008 --summary-file html:path).
#[derive(Debug, Default)]
pub struct HtmlReporter;

impl HtmlReporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for HtmlReporter {
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError> {
        writeln!(
            w,
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>vlz report</title></head><body>"
        )?;
        writeln!(w, "<h1>Vulnerability report</h1>")?;
        if data.findings.is_empty() {
            writeln!(w, "<p>No vulnerabilities found.</p>")?;
        } else {
            writeln!(
                w,
                "<table border=\"1\"><thead><tr><th>Package</th><th>Version</th><th>CVE ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>"
            )?;
            for (pkg, recs) in &data.findings {
                for (cve, severity) in recs {
                    let desc_escaped = html_escape(&cve.description);
                    writeln!(
                        w,
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&pkg.name),
                        html_escape(&pkg.version),
                        html_escape(&cve.id),
                        severity.as_str(),
                        desc_escaped
                    )?;
                }
            }
            writeln!(w, "</tbody></table>")?;
        }
        writeln!(w, "</body></html>")?;
        w.flush()?;
        Ok(())
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Reporter that outputs SARIF 2.1.0 JSON (FR-008 --summary-file sarif:path).
#[derive(Debug, Default)]
pub struct SarifReporter;

impl SarifReporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for SarifReporter {
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError> {
        let results: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|(pkg, recs)| {
                recs.iter().map(|(cve, severity)| {
                    serde_json::json!({
                        "ruleId": cve.id,
                        "level": severity_level_sarif(severity),
                        "message": { "text": cve.description },
                        "properties": {
                            "package": pkg.name,
                            "version": pkg.version,
                            "severity": severity.as_str()
                        }
                    })
                })
            })
            .collect();
        let rules: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|(_, recs)| recs.iter().map(|(cve, _)| cve.id.clone()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "shortDescription": { "text": id },
                    "helpUri": format!("https://nvd.nist.gov/vuln/detail/{}", id)
                })
            })
            .collect();
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "vlz",
                        "informationUri": "https://github.com/your-org/verilyze",
                        "rules": rules
                    }
                },
                "results": results
            }]
        });
        let s = serde_json::to_string_pretty(&sarif)?;
        writeln!(w, "{}", s).map_err(ReportError::Io)?;
        w.flush()?;
        Ok(())
    }
}

fn severity_level_sarif(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "error",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "warning",
        Severity::Unknown => "note",
    }
}

/// PURL for a Python package (pypi ecosystem; SEC-019 CycloneDX 1.6).
fn purl_pypi(name: &str, version: &str) -> String {
    format!("pkg:pypi/{}@{}", name, version)
}

/// RFC 3339 timestamp for BOM metadata (no external deps).
fn format_timestamp_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (y, m, d, h, min, s) = secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, min, s)
}

fn secs_to_ymdhms(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    const SECS_PER_DAY: u64 = 86400;
    let days = secs / SECS_PER_DAY;
    let rem = secs % SECS_PER_DAY;
    let h = rem / 3600;
    let rem = rem % 3600;
    let min = rem / 60;
    let s = rem % 60;
    let (y, m, d) = days_to_ymd(days);
    (y, m, d, h, min, s)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut d = days as i64 + 719468;
    let era = if d >= 0 {
        d / 146097
    } else {
        (d - 146096) / 146097
    };
    d -= era * 146097;
    let doe = if d >= 0 { d } else { d + 146097 };
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe + era * 400) as u64 + 1970;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u64;
    let y = if mp >= 10 { y + 1 } else { y };
    (y, m, d)
}

/// Reporter that outputs CycloneDX 1.6 BOM JSON (SEC-019, FR-008).
#[derive(Debug, Default)]
pub struct CycloneDxReporter;

impl CycloneDxReporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for CycloneDxReporter {
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError> {
        let packages: Vec<&Package> = data
            .all_packages
            .as_ref()
            .map(|v| v.iter().collect())
            .unwrap_or_else(|| {
                data.findings.iter().map(|(p, _)| p).collect::<Vec<_>>()
            });
        let components: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                let bom_ref = purl_pypi(&p.name, &p.version);
                serde_json::json!({
                    "type": "library",
                    "name": p.name,
                    "version": p.version,
                    "bom-ref": bom_ref,
                    "purl": bom_ref
                })
            })
            .collect();
        let vulnerabilities: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|(pkg, recs)| {
                recs.iter().map(|(cve, severity)| {
                    let bom_ref = purl_pypi(&pkg.name, &pkg.version);
                    let mut vuln = serde_json::json!({
                        "id": cve.id,
                        "description": cve.description,
                        "affects": [{ "ref": bom_ref }]
                    });
                    if let Some(score) = cve.cvss_score {
                        let method = match cve.cvss_version {
                            Some(CvssVersion::V2) => "CVSSv2",
                            Some(CvssVersion::V3) => "CVSSv3",
                            Some(CvssVersion::V4) => "CVSSv4",
                            None => "CVSSv3",
                        };
                        let severity_str = match severity {
                            Severity::Critical => "Critical",
                            Severity::High => "High",
                            Severity::Medium => "Medium",
                            Severity::Low => "Low",
                            Severity::Unknown => "Unknown",
                        };
                        if let Some(obj) = vuln.as_object_mut() {
                            obj.insert(
                                "ratings".to_string(),
                                serde_json::json!([{
                                    "method": method,
                                    "score": score,
                                    "severity": severity_str
                                }]),
                            );
                        }
                    }
                    vuln
                })
            })
            .collect();
        let bom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": format_timestamp_rfc3339(),
                "tools": [{ "name": "vlz", "vendor": "verilyze" }]
            },
            "components": components,
            "vulnerabilities": vulnerabilities
        });
        let s = serde_json::to_string_pretty(&bom)?;
        writeln!(w, "{}", s).map_err(ReportError::Io)?;
        w.flush()?;
        Ok(())
    }
}

/// SPDX ID for a Python package (SEC-019 SPDX 3.0).
fn spdx_id_pkg(name: &str, version: &str) -> String {
    format!(
        "urn:spdx.dev:pkg-pypi-{}-{}",
        name.replace(['.', '-', '_'], "-"),
        version.replace(['.', '-', '_'], "-")
    )
}

/// SPDX ID for a vulnerability (SEC-019 SPDX 3.0).
fn spdx_id_vuln(cve_id: &str) -> String {
    format!("urn:spdx.dev:vuln-{}", cve_id.replace('.', "-"))
}

/// Reporter that outputs SPDX 3.0 JSON (SEC-019, FR-008).
#[derive(Debug, Default)]
pub struct SpdxReporter;

impl SpdxReporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for SpdxReporter {
    async fn render_to_writer(
        &self,
        data: &ReportData,
        w: &mut (dyn std::io::Write + Send),
    ) -> Result<(), ReportError> {
        let packages: Vec<&Package> = data
            .all_packages
            .as_ref()
            .map(|v| v.iter().collect())
            .unwrap_or_else(|| {
                data.findings.iter().map(|(p, _)| p).collect::<Vec<_>>()
            });
        let pkg_elements: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                let sid = spdx_id_pkg(&p.name, &p.version);
                serde_json::json!({
                    "@type": "Package",
                    "spdxId": sid,
                    "name": p.name,
                    "versionInfo": p.version,
                    "packageUrl": purl_pypi(&p.name, &p.version)
                })
            })
            .collect();
        let vuln_elements: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|(_pkg, recs)| {
                recs.iter().map(|(cve, _)| {
                    let vuln_id = spdx_id_vuln(&cve.id);
                    serde_json::json!({
                        "@type": "Vulnerability",
                        "spdxId": vuln_id,
                        "description": cve.description,
                        "externalIdentifier": {
                            "@type": "ExternalIdentifier",
                            "externalIdentifierType": "securityAdvisory",
                            "identifier": cve.id,
                            "identifierLocation": format!("https://nvd.nist.gov/vuln/detail/{}", cve.id)
                        }
                    })
                })
            })
            .collect();
        let relationships: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|(pkg, recs)| {
                recs.iter().map(|(cve, _)| {
                    serde_json::json!({
                        "@type": "Relationship",
                        "relationshipType": "hasAssociatedVulnerability",
                        "from": spdx_id_pkg(&pkg.name, &pkg.version),
                        "to": [spdx_id_vuln(&cve.id)]
                    })
                })
            })
            .collect();
        let elements: Vec<serde_json::Value> =
            pkg_elements.into_iter().chain(vuln_elements).collect();
        let doc_id = format!(
            "urn:spdx.dev:doc-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let spdx = serde_json::json!({
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@type": "SpdxDocument",
            "spdxId": doc_id,
            "creationInfo": {
                "created": format_timestamp_rfc3339(),
                "createdBy": ["urn:spdx.dev:tool-vlz"],
                "profile": ["Core", "Software"]
            },
            "element": elements,
            "relationship": relationships
        });
        let s = serde_json::to_string_pretty(&spdx)?;
        writeln!(w, "{}", s).map_err(ReportError::Io)?;
        w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_severity_none_returns_unknown() {
        let config = SeverityConfig::default();
        assert_eq!(
            resolve_severity(None, Some(CvssVersion::V3), &config),
            Severity::Unknown
        );
        assert_eq!(
            resolve_severity(Some(7.0), None, &config),
            Severity::Unknown
        );
    }

    #[test]
    fn resolve_severity_default_thresholds_fr013() {
        let config = SeverityConfig::default();
        assert_eq!(
            resolve_severity(Some(9.5), Some(CvssVersion::V3), &config),
            Severity::Critical
        );
        assert_eq!(
            resolve_severity(Some(7.5), Some(CvssVersion::V3), &config),
            Severity::High
        );
        assert_eq!(
            resolve_severity(Some(5.0), Some(CvssVersion::V3), &config),
            Severity::Medium
        );
        assert_eq!(
            resolve_severity(Some(0.5), Some(CvssVersion::V3), &config),
            Severity::Low
        );
        assert_eq!(
            resolve_severity(Some(0.0), Some(CvssVersion::V3), &config),
            Severity::Unknown
        );
    }

    #[test]
    fn resolve_severity_per_version_uses_correct_thresholds() {
        let config = SeverityConfig::default();
        assert_eq!(
            resolve_severity(Some(8.0), Some(CvssVersion::V2), &config),
            Severity::High
        );
        assert_eq!(
            resolve_severity(Some(8.0), Some(CvssVersion::V4), &config),
            Severity::High
        );
    }

    fn sample_report_data_empty() -> ReportData {
        ReportData {
            findings: vec![],
            all_packages: None,
        }
    }

    fn sample_report_data_one_finding() -> ReportData {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            ..Default::default()
        };
        let cve = CveRecord {
            id: "CVE-2023-1234".to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "A bug".to_string(),
            reachable: None,
        };
        ReportData {
            findings: vec![(pkg, vec![(cve, Severity::High)])],
            all_packages: None,
        }
    }

    fn sample_report_data_with_all_packages() -> ReportData {
        let pkg_foo = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            ..Default::default()
        };
        let pkg_bar = Package {
            name: "bar".to_string(),
            version: "2.0".to_string(),
            ..Default::default()
        };
        let cve = CveRecord {
            id: "CVE-2023-1234".to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "A bug".to_string(),
            reachable: None,
        };
        ReportData {
            findings: vec![(pkg_foo.clone(), vec![(cve, Severity::High)])],
            all_packages: Some(vec![pkg_foo, pkg_bar]),
        }
    }

    #[tokio::test]
    async fn default_reporter_empty_findings() {
        let data = sample_report_data_empty();
        let mut buf = Vec::new();
        DefaultReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("No vulnerabilities found."));
    }

    #[tokio::test]
    async fn default_reporter_one_finding() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        DefaultReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("foo"));
        assert!(out.contains("CVE-2023-1234"));
        assert!(out.contains("HIGH"));
    }

    #[tokio::test]
    async fn json_reporter_empty_findings() {
        let data = sample_report_data_empty();
        let mut buf = Vec::new();
        JsonReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap();
        assert!(
            parsed
                .get("findings")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn json_reporter_one_finding() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        JsonReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap();
        let findings = parsed.get("findings").unwrap().as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].get("package").unwrap().get("name").unwrap(),
            "foo"
        );
        let cves = findings[0].get("cves").unwrap().as_array().unwrap();
        assert_eq!(cves[0].get("severity").unwrap(), "HIGH");
    }

    #[tokio::test]
    async fn html_reporter_contains_table_and_escapes() {
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
            ..Default::default()
        };
        let cve = CveRecord {
            id: "CVE-X".to_string(),
            cvss_score: None,
            cvss_version: None,
            description: "a <b> & \"quoted\"".to_string(),
            reachable: None,
        };
        let data = ReportData {
            findings: vec![(pkg, vec![(cve, Severity::Medium)])],
            all_packages: None,
        };
        let mut buf = Vec::new();
        HtmlReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("<table"));
        assert!(out.contains("&lt;"));
        assert!(out.contains("&amp;"));
        assert!(out.contains("&quot;"));
    }

    #[tokio::test]
    async fn sarif_reporter_contains_schema_version_and_results() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("$schema"));
        assert!(out.contains("2.1.0"));
        let parsed: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap();
        let runs = parsed.get("runs").unwrap().as_array().unwrap();
        let results = runs[0].get("results").unwrap().as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get("ruleId").unwrap(), "CVE-2023-1234");
        assert!(results[0].get("message").is_some());
    }

    #[tokio::test]
    async fn sarif_reporter_has_required_schema_fields() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        assert!(parsed.get("$schema").is_some());
        assert_eq!(parsed.get("version").unwrap(), "2.1.0");
        let runs = parsed.get("runs").unwrap().as_array().unwrap();
        assert!(!runs.is_empty());
        let driver = runs[0].get("tool").unwrap().get("driver").unwrap();
        assert!(driver.get("name").is_some());
        assert!(driver.get("rules").is_some());
    }

    #[tokio::test]
    async fn sarif_reporter_includes_rules_for_each_cve() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let rules = parsed
            .get("runs")
            .unwrap()
            .get(0)
            .unwrap()
            .get("tool")
            .unwrap()
            .get("driver")
            .unwrap()
            .get("rules")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].get("id").unwrap(), "CVE-2023-1234");
    }

    #[tokio::test]
    async fn cyclonedx_reporter_empty_findings_produces_valid_bom() {
        let data = ReportData {
            findings: vec![],
            all_packages: Some(vec![]),
        };
        let mut buf = Vec::new();
        CycloneDxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        assert_eq!(parsed.get("bomFormat").unwrap(), "CycloneDX");
        assert_eq!(parsed.get("specVersion").unwrap(), "1.6");
        assert!(parsed.get("metadata").is_some());
        let components = parsed.get("components").unwrap().as_array().unwrap();
        assert!(components.is_empty());
    }

    #[tokio::test]
    async fn cyclonedx_reporter_includes_all_packages_as_components() {
        let data = sample_report_data_with_all_packages();
        let mut buf = Vec::new();
        CycloneDxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let components = parsed.get("components").unwrap().as_array().unwrap();
        assert_eq!(components.len(), 2);
        let names: Vec<&str> = components
            .iter()
            .map(|c| c.get("name").unwrap().as_str().unwrap())
            .collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
        assert!(
            components[0]
                .get("bom-ref")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("pkg:pypi/")
        );
    }

    #[tokio::test]
    async fn cyclonedx_reporter_includes_vulnerabilities_with_affects() {
        let data = sample_report_data_with_all_packages();
        let mut buf = Vec::new();
        CycloneDxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let vulns = parsed.get("vulnerabilities").unwrap().as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].get("id").unwrap(), "CVE-2023-1234");
        let affects = vulns[0].get("affects").unwrap().as_array().unwrap();
        assert_eq!(affects.len(), 1);
        assert_eq!(affects[0].get("ref").unwrap(), "pkg:pypi/foo@1.0");
    }

    #[tokio::test]
    async fn cyclonedx_reporter_schema_key_fields() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        CycloneDxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        assert_eq!(parsed.get("bomFormat").unwrap(), "CycloneDX");
        assert_eq!(parsed.get("specVersion").unwrap(), "1.6");
        assert!(parsed.get("metadata").is_some());
        assert!(parsed.get("components").is_some());
        assert!(parsed.get("vulnerabilities").is_some());
    }

    #[tokio::test]
    async fn spdx_reporter_empty_produces_valid_document() {
        let data = ReportData {
            findings: vec![],
            all_packages: Some(vec![]),
        };
        let mut buf = Vec::new();
        SpdxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        assert!(parsed.get("@context").is_some());
        assert!(parsed.get("@type").is_some());
        assert_eq!(parsed.get("@type").unwrap(), "SpdxDocument");
        assert!(parsed.get("spdxId").is_some());
        assert!(parsed.get("creationInfo").is_some());
    }

    #[tokio::test]
    async fn spdx_reporter_includes_packages_as_elements() {
        let data = sample_report_data_with_all_packages();
        let mut buf = Vec::new();
        SpdxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let elements = parsed.get("element").unwrap().as_array().unwrap();
        let pkg_count = elements
            .iter()
            .filter(|e| {
                e.get("@type").and_then(|t| t.as_str()) == Some("Package")
            })
            .count();
        assert!(pkg_count >= 2);
    }

    #[tokio::test]
    async fn spdx_reporter_includes_vulnerabilities_and_relationships() {
        let data = sample_report_data_with_all_packages();
        let mut buf = Vec::new();
        SpdxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let elements = parsed.get("element").unwrap().as_array().unwrap();
        let vuln_count = elements
            .iter()
            .filter(|e| {
                e.get("@type").and_then(|t| t.as_str())
                    == Some("Vulnerability")
            })
            .count();
        assert_eq!(vuln_count, 1);
        let rels = parsed.get("relationship").unwrap().as_array().unwrap();
        assert!(!rels.is_empty());
        assert_eq!(
            rels[0].get("relationshipType").unwrap(),
            "hasAssociatedVulnerability"
        );
    }

    #[tokio::test]
    async fn spdx_reporter_uses_external_identifier_for_cve() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        SpdxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let elements = parsed.get("element").unwrap().as_array().unwrap();
        let vuln = elements
            .iter()
            .find(|e| {
                e.get("@type").and_then(|t| t.as_str())
                    == Some("Vulnerability")
            })
            .unwrap();
        assert_eq!(
            vuln.get("externalIdentifier")
                .unwrap()
                .get("identifier")
                .unwrap(),
            "CVE-2023-1234"
        );
    }
}
