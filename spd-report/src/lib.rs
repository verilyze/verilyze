// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

#![deny(unsafe_code)]

use async_trait::async_trait;
use serde::Serialize;
use spd_db::{CveRecord, CvssVersion, Package, Severity};
use std::io::Write;

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
#[derive(Debug, Clone)]
pub struct SeverityConfig {
    pub v2: SeverityThresholds,
    pub v3: SeverityThresholds,
    pub v4: SeverityThresholds,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            v2: SeverityThresholds::default(),
            v3: SeverityThresholds::default(),
            v4: SeverityThresholds::default(),
        }
    }
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
                let truncated: String = chars.by_ref().take(DESCRIPTION_MAX_LEN).collect();
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
                    pkg.name, pkg.version, cve.id, severity_display, desc_display
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
        writeln!(w, "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>spd report</title></head><body>")?;
        writeln!(w, "<h1>Vulnerability report</h1>")?;
        if data.findings.is_empty() {
            writeln!(w, "<p>No vulnerabilities found.</p>")?;
        } else {
            writeln!(w, "<table border=\"1\"><thead><tr><th>Package</th><th>Version</th><th>CVE ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>")?;
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
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "spd", "informationUri": "https://github.com/your-org/super-duper" } },
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
        ReportData { findings: vec![] }
    }

    fn sample_report_data_one_finding() -> ReportData {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
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
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert!(parsed
            .get("findings")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
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
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
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
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let runs = parsed.get("runs").unwrap().as_array().unwrap();
        let results = runs[0].get("results").unwrap().as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get("ruleId").unwrap(), "CVE-2023-1234");
        assert!(results[0].get("message").is_some());
    }
}
