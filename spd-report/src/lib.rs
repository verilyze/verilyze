//! Trait responsible for rendering the final report.
#![deny(unsafe_code)]

use async_trait::async_trait;
use serde::Serialize;
use std::io::Write;
use spd_db::{CveRecord, CvssVersion, Package, Severity};

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
    let Some(s) = score else { return Severity::Unknown };
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

    #[error("{0}")]
    Other(String),
}

/// Simple data structure handed to the reporter. Each CVE has a pre-resolved severity (FR-013).
pub struct ReportData {
    pub findings: Vec<(Package, Vec<(CveRecord, Severity)>)>,
}

#[async_trait]
pub trait Reporter: Send + Sync {
    /// Render the report to stdout (or a file, depending on CLI flags).
    async fn render(&self, data: &ReportData) -> Result<(), ReportError>;
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
    async fn render(&self, data: &ReportData) -> Result<(), ReportError> {
        let mut out = std::io::stdout().lock();
        if data.findings.is_empty() {
            writeln!(out, "No vulnerabilities found.")?;
            return Ok(());
        }
        writeln!(out, "Package | Version | CVE ID | Severity | Description")?;
        writeln!(out, "{}", "-".repeat(80))?;
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
                    out,
                    "{} | {} | {} | {} | {}",
                    pkg.name, pkg.version, cve.id, severity_display, desc_display
                )?;
            }
        }
        out.flush()?;
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

/// Reporter that outputs findings as JSON to stdout (FR-007 --format-type json).
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
    async fn render(&self, data: &ReportData) -> Result<(), ReportError> {
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
        let mut out = std::io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &report)
            .map_err(|e| ReportError::Other(e.to_string()))?;
        writeln!(out).map_err(ReportError::Io)?;
        out.flush()?;
        Ok(())
    }
}
