// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use async_trait::async_trait;

/// Project repository URL; used in SARIF informationUri and elsewhere (DRY).
pub const VLZ_REPOSITORY_URL: &str = "https://github.com/verilyze/verilyze";

/// JSON Schema `$id` for `--format json` reports (DOC-005).
pub const REPORT_JSON_SCHEMA_ID: &str =
    "https://github.com/verilyze/verilyze/schemas/v1/report.json";

use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use vlz_db::{
    CRATES_IO_ECOSYSTEM, CveEvidenceLocation, CveRecord, CvssVersion,
    DeclarationKind, GO_ECOSYSTEM, MAX_DECLARATIONS_PER_FINDING,
    PYPI_ECOSYSTEM, Package, PackageDeclarationLocation, Severity,
    dedupe_sort_declarations,
};

const DESCRIPTION_MAX_LEN: usize = 60;

/// Plain/HTML message when scan completed with no CVE findings (FR-010).
pub const NO_VULNERABILITIES_FOUND_MESSAGE: &str = "No vulnerabilities found.";
/// Plain/HTML message when findings are empty but analysis did not complete (FR-010).
pub const SCAN_INCOMPLETE_MESSAGE: &str =
    "Scan incomplete; see manifest coverage and stderr for details.";
/// Plain/HTML message when findings are empty but some manifests were direct-only (FR-010, FR-022a).
pub const DEGRADED_COVERAGE_NO_VULNERABILITIES_MESSAGE: &str = "No vulnerabilities found in scanned packages; see manifest coverage for incomplete resolution.";

/// Format a single path relative to scan root when possible (FR-037).
fn relative_path_string(
    path: &std::path::Path,
    root: Option<&std::path::Path>,
) -> String {
    if let Some(root) = root {
        path.strip_prefix(root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned())
    } else {
        path.to_string_lossy().into_owned()
    }
}

/// True when plain/HTML manifest coverage section should be shown (FR-037).
pub fn manifest_coverage_needs_section(
    coverage: &[ManifestCoverageEntry],
) -> bool {
    coverage
        .iter()
        .any(|e| e.status != ManifestScanStatus::ScannedTransitive)
}

fn write_manifest_coverage_plain(
    w: &mut (dyn std::io::Write + Send),
    coverage: &[ManifestCoverageEntry],
    root_path: Option<&std::path::Path>,
) -> Result<(), ReportError> {
    if !manifest_coverage_needs_section(coverage) {
        return Ok(());
    }
    writeln!(w, "Manifest coverage:")?;
    writeln!(w, "Path | Language | Status | Direct-only reason | Error")?;
    writeln!(w, "{}", "-".repeat(100))?;
    for entry in coverage {
        let path = relative_path_string(&entry.path, root_path);
        let direct_only = entry.direct_only_reason.as_deref().unwrap_or("-");
        let error = entry.error.as_deref().unwrap_or("-");
        writeln!(
            w,
            "{} | {} | {} | {} | {}",
            path,
            entry.language,
            entry.status.as_str(),
            direct_only,
            error
        )?;
    }
    writeln!(w)?;
    Ok(())
}

#[derive(Serialize)]
struct JsonManifestCoverageEntry<'a> {
    path: String,
    language: &'a str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_only_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

fn json_manifest_coverage_entries<'a>(
    coverage: &'a [ManifestCoverageEntry],
    root_path: Option<&std::path::Path>,
) -> Vec<JsonManifestCoverageEntry<'a>> {
    coverage
        .iter()
        .map(|entry| JsonManifestCoverageEntry {
            path: relative_path_string(&entry.path, root_path),
            language: &entry.language,
            status: entry.status.as_str(),
            direct_only_reason: entry.direct_only_reason.as_deref(),
            error: entry.error.as_deref(),
        })
        .collect()
}

fn manifest_coverage_json_array(
    coverage: &[ManifestCoverageEntry],
    root_path: Option<&std::path::Path>,
) -> Vec<serde_json::Value> {
    json_manifest_coverage_entries(coverage, root_path)
        .into_iter()
        .map(|entry| {
            serde_json::to_value(entry).expect("manifest coverage entry")
        })
        .collect()
}

/// Format manifest paths for display. When root_path is provided, makes paths relative.
fn format_manifest_paths(
    paths: &[PathBuf],
    root_path: Option<&std::path::Path>,
) -> String {
    if paths.is_empty() {
        return "-".to_string();
    }
    let formatted: Vec<String> = paths
        .iter()
        .map(|p| relative_path_string(p.as_path(), root_path))
        .collect();
    if formatted.len() <= 2 {
        formatted.join(", ")
    } else {
        format!("{} (+{} more)", formatted[0], formatted.len() - 1)
    }
}

fn format_evidence_location(loc: &CveEvidenceLocation) -> String {
    format!("{}:{} ({})", loc.path, loc.start_line, loc.symbol)
}

fn format_cve_symbol_details(cve: &CveRecord) -> Option<String> {
    if cve.advisory_symbols.is_empty()
        && cve.evidence.is_empty()
        && cve.symbol_usage.is_none()
    {
        return None;
    }
    let mut parts = Vec::new();
    if !cve.advisory_symbols.is_empty() {
        parts.push(format!(
            "advisory_symbols: {}",
            cve.advisory_symbols.join(", ")
        ));
    }
    if let Some(usage) = cve.symbol_usage.as_deref() {
        parts.push(format!("symbol_usage: {usage}"));
    }
    if !cve.evidence.is_empty() {
        let sites: Vec<String> =
            cve.evidence.iter().map(format_evidence_location).collect();
        parts.push(format!("evidence: {}", sites.join("; ")));
    }
    Some(parts.join("; "))
}

fn format_declarations(
    declarations: &[PackageDeclarationLocation],
    root_path: Option<&std::path::Path>,
) -> String {
    if declarations.is_empty() {
        return String::new();
    }
    let formatted: Vec<String> = declarations
        .iter()
        .map(|decl| {
            let path = relative_path_string(
                std::path::Path::new(&decl.path),
                root_path,
            );
            format!("{path}:{}", decl.start_line)
        })
        .collect();
    if formatted.len() <= 2 {
        formatted.join(", ")
    } else {
        format!("{} (+{} more)", formatted[0], formatted.len() - 1)
    }
}

fn sarif_physical_location(
    uri: &str,
    start_line: Option<u32>,
    end_line: Option<u32>,
) -> serde_json::Value {
    let mut physical = serde_json::json!({
        "artifactLocation": { "uri": uri }
    });
    if let Some(line) = start_line {
        let mut region = serde_json::json!({ "startLine": line });
        if let Some(end) = end_line {
            region["endLine"] = serde_json::json!(end);
        }
        physical["region"] = region;
    }
    serde_json::json!({ "physicalLocation": physical })
}

fn sarif_evidence_location(
    loc: &CveEvidenceLocation,
    root: Option<&std::path::Path>,
) -> serde_json::Value {
    let mut location = sarif_physical_location(
        &sarif_uri_for_path(&loc.path, root),
        Some(loc.start_line),
        loc.end_line,
    );
    location["properties"] = serde_json::json!({
        "location_kind": "evidence",
        "symbol": loc.symbol,
    });
    location["message"] =
        serde_json::json!({ "text": "First-party advisory symbol usage" });
    location
}

fn sarif_declaration_location(
    decl: &PackageDeclarationLocation,
    root: Option<&std::path::Path>,
) -> serde_json::Value {
    let mut location = sarif_physical_location(
        &sarif_uri_for_path(&decl.path, root),
        Some(decl.start_line),
        decl.end_line,
    );
    location["properties"] = serde_json::json!({
        "location_kind": "declaration",
        "declaration_kind": match decl.kind {
            DeclarationKind::Manifest => "manifest",
            DeclarationKind::Lockfile => "lockfile",
        },
    });
    location["message"] =
        serde_json::json!({ "text": "Dependency declaration" });
    location
}

fn sarif_declaration_locations(
    declarations: &[PackageDeclarationLocation],
    root: Option<&std::path::Path>,
) -> Vec<serde_json::Value> {
    let mut sorted = declarations.to_vec();
    dedupe_sort_declarations(&mut sorted);
    sorted
        .into_iter()
        .take(MAX_DECLARATIONS_PER_FINDING)
        .map(|decl| sarif_declaration_location(&decl, root))
        .collect()
}

fn sarif_uri_for_path(path: &str, root: Option<&std::path::Path>) -> String {
    let rel = if let Some(root) = root {
        std::path::Path::new(path)
            .strip_prefix(root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string())
    } else {
        path.to_string()
    };
    sarif_percent_encode_path(&rel)
}

fn sarif_percent_encode_path(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .map(percent_encode_sarif_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_sarif_segment(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b'@' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

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

/// A single finding: a vulnerable package with its manifest path(s) and CVEs.
#[derive(Debug, Clone)]
pub struct Finding {
    pub package: Package,
    /// Manifest file path(s) that introduce this package. Sorted and deduplicated.
    pub manifest_paths: Vec<PathBuf>,
    /// Declaration line locations (FR-036a Tier 1). Sorted and deduplicated.
    pub declarations: Vec<PackageDeclarationLocation>,
    pub cves: Vec<(CveRecord, Severity)>,
}

/// Manifest scan outcome for multi-manifest resilience (FR-037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestScanStatus {
    ScannedTransitive,
    ScannedDirectOnly,
    FailedParse,
    FailedResolution,
}

/// JSON/status string for `scanned_transitive` (NFR-024).
pub const MANIFEST_STATUS_SCANNED_TRANSITIVE: &str = "scanned_transitive";
/// JSON/status string for `scanned_direct_only` (NFR-024).
pub const MANIFEST_STATUS_SCANNED_DIRECT_ONLY: &str = "scanned_direct_only";
/// JSON/status string for `failed_parse` (NFR-024).
pub const MANIFEST_STATUS_FAILED_PARSE: &str = "failed_parse";
/// JSON/status string for `failed_resolution` (NFR-024).
pub const MANIFEST_STATUS_FAILED_RESOLUTION: &str = "failed_resolution";

impl ManifestScanStatus {
    /// Stable snake_case label for reports and JSON (FR-037).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScannedTransitive => MANIFEST_STATUS_SCANNED_TRANSITIVE,
            Self::ScannedDirectOnly => MANIFEST_STATUS_SCANNED_DIRECT_ONLY,
            Self::FailedParse => MANIFEST_STATUS_FAILED_PARSE,
            Self::FailedResolution => MANIFEST_STATUS_FAILED_RESOLUTION,
        }
    }

    /// True when this status should cause exit 4 (FR-037).
    pub fn is_blocking(self) -> bool {
        matches!(self, Self::FailedParse | Self::FailedResolution)
    }
}

/// Per-manifest scan coverage entry (FR-037).
#[derive(Debug, Clone)]
pub struct ManifestCoverageEntry {
    pub path: PathBuf,
    pub language: String,
    pub status: ManifestScanStatus,
    pub direct_only_reason: Option<String>,
    pub error: Option<String>,
}

/// Simple data structure handed to the reporter. Each CVE has a pre-resolved severity (FR-013).
/// FR-015a: project_id is included when the scan was run with --project-id (or config/env).
pub struct ReportData {
    pub findings: Vec<Finding>,
    /// All resolved packages (for SBOM formats). When Some, SBOM reporters list all components.
    pub all_packages: Option<Vec<Package>>,
    /// Project ID for audit trail (FR-015a). Present when scan used --project-id or equivalent.
    pub project_id: Option<String>,
    /// Scan root for path normalization (relative paths in reports). When Some, paths are
    /// made relative to this root when possible.
    pub root_path: Option<PathBuf>,
    /// Per-manifest scan status (FR-037). Empty when no manifests were discovered.
    pub manifest_coverage: Vec<ManifestCoverageEntry>,
    /// True when `--offline` blocked a required CVE lookup (FR-031).
    pub offline_cache_miss: bool,
    /// True when CVE provider fetch failed after retries (FR-010).
    pub provider_fetch_failed: bool,
}

impl ReportData {
    /// True when the scan did not fully complete (FR-010).
    pub fn is_analysis_incomplete(&self) -> bool {
        self.offline_cache_miss
            || self.provider_fetch_failed
            || self
                .manifest_coverage
                .iter()
                .any(|e| e.status.is_blocking())
    }

    /// True when any manifest was scanned with direct dependencies only (FR-022a).
    pub fn has_degraded_coverage(&self) -> bool {
        self.manifest_coverage
            .iter()
            .any(|e| e.status == ManifestScanStatus::ScannedDirectOnly)
    }

    /// Message for empty findings in plain/HTML reports (FR-010).
    pub fn empty_findings_message(&self) -> &'static str {
        if self.is_analysis_incomplete() {
            SCAN_INCOMPLETE_MESSAGE
        } else if self.has_degraded_coverage() {
            DEGRADED_COVERAGE_NO_VULNERABILITIES_MESSAGE
        } else {
            NO_VULNERABILITIES_FOUND_MESSAGE
        }
    }
}

#[async_trait]
pub trait Reporter: Send + Sync {
    /// Render the report to the given writer (used for stdout and --report).
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

    /// Render the report to a file (FR-008 --report / --summary-file).
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
        if let Some(ref pid) = data.project_id {
            writeln!(w, "Project: {}", pid)?;
        }
        write_manifest_coverage_plain(
            w,
            &data.manifest_coverage,
            data.root_path.as_deref(),
        )?;
        if data.findings.is_empty() {
            writeln!(w, "{}", data.empty_findings_message())?;
            w.flush()?;
            return Ok(());
        }
        writeln!(
            w,
            "Package | Version | CVE ID | Severity | Manifest(s) | Description"
        )?;
        writeln!(w, "{}", "-".repeat(100))?;
        for finding in &data.findings {
            let mut manifests_display = format_manifest_paths(
                &finding.manifest_paths,
                data.root_path.as_deref(),
            );
            let decl_display = format_declarations(
                &finding.declarations,
                data.root_path.as_deref(),
            );
            if !decl_display.is_empty() {
                manifests_display =
                    format!("{manifests_display}; decl: {decl_display}");
            }
            for (idx, (cve, severity)) in finding.cves.iter().enumerate() {
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
                if idx == 0 {
                    writeln!(
                        w,
                        "{} | {} | {} | {} | {} | {}",
                        finding.package.name,
                        finding.package.version,
                        cve.id,
                        severity_display,
                        manifests_display,
                        desc_display
                    )?;
                } else {
                    writeln!(
                        w,
                        "  |  | {} | {} |  | {}",
                        cve.id, severity_display, desc_display
                    )?;
                }
                if let Some(details) = format_cve_symbol_details(cve) {
                    writeln!(w, "  {details}")?;
                }
            }
        }
        w.flush()?;
        Ok(())
    }
}

/// JSON report shape: findings array of { package, cves } with severity per CVE.
/// FR-015a: project_id included when scan used --project-id.
#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<&'a str>,
    manifest_coverage: Vec<JsonManifestCoverageEntry<'a>>,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    package: &'a Package,
    #[serde(serialize_with = "serialize_manifest_paths")]
    manifest_paths: &'a [PathBuf],
    #[serde(
        default,
        skip_serializing_if = "<[PackageDeclarationLocation]>::is_empty"
    )]
    declarations: &'a [PackageDeclarationLocation],
    cves: Vec<JsonCveWithSeverity<'a>>,
}

fn serialize_manifest_paths<S>(
    paths: &[PathBuf],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    strs.serialize(serializer)
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
            schema: REPORT_JSON_SCHEMA_ID,
            project_id: data.project_id.as_deref(),
            manifest_coverage: json_manifest_coverage_entries(
                &data.manifest_coverage,
                data.root_path.as_deref(),
            ),
            findings: data
                .findings
                .iter()
                .map(|f| JsonFinding {
                    package: &f.package,
                    manifest_paths: &f.manifest_paths,
                    declarations: &f.declarations,
                    cves: f
                        .cves
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

/// Reporter that outputs a minimal HTML table (FR-008 --report html:path).
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
        if let Some(ref pid) = data.project_id {
            writeln!(
                w,
                "<p><strong>Project:</strong> {}</p>",
                html_escape(pid)
            )?;
        }
        if manifest_coverage_needs_section(&data.manifest_coverage) {
            writeln!(w, "<h2>Manifest coverage</h2>")?;
            writeln!(
                w,
                "<table border=\"1\"><thead><tr><th>Path</th><th>Language</th><th>Status</th><th>Direct-only reason</th><th>Error</th></tr></thead><tbody>"
            )?;
            for entry in &data.manifest_coverage {
                let path = html_escape(&relative_path_string(
                    &entry.path,
                    data.root_path.as_deref(),
                ));
                let direct_only = html_escape(
                    entry.direct_only_reason.as_deref().unwrap_or("-"),
                );
                let error = html_escape(entry.error.as_deref().unwrap_or("-"));
                writeln!(
                    w,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    path,
                    html_escape(&entry.language),
                    entry.status.as_str(),
                    direct_only,
                    error
                )?;
            }
            writeln!(w, "</tbody></table>")?;
        }
        if data.findings.is_empty() {
            writeln!(
                w,
                "<p>{}</p>",
                html_escape(data.empty_findings_message())
            )?;
        } else {
            writeln!(
                w,
                "<table border=\"1\"><thead><tr><th>Package</th><th>Version</th><th>CVE ID</th><th>Severity</th><th>Manifest(s)</th><th>Description</th></tr></thead><tbody>"
            )?;
            for finding in &data.findings {
                let manifests_display = format_manifest_paths(
                    &finding.manifest_paths,
                    data.root_path.as_deref(),
                );
                for (cve, severity) in &finding.cves {
                    let desc_escaped = html_escape(&cve.description);
                    writeln!(
                        w,
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&finding.package.name),
                        html_escape(&finding.package.version),
                        html_escape(&cve.id),
                        severity.as_str(),
                        html_escape(&manifests_display),
                        desc_escaped
                    )?;
                    if let Some(details) = format_cve_symbol_details(cve) {
                        writeln!(
                            w,
                            "<tr><td colspan=\"6\"><em>{}</em></td></tr>",
                            html_escape(&details)
                        )?;
                    }
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

/// Reporter that outputs SARIF 2.1.0 JSON (FR-008 --report sarif:path).
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
            .flat_map(|finding| {
                finding.cves.iter().map(|(cve, severity)| {
                    let manifest_uris: Vec<String> = finding
                        .manifest_paths
                        .iter()
                        .map(|p| {
                            relative_path_string(
                                p.as_path(),
                                data.root_path.as_deref(),
                            )
                        })
                        .collect();
                    let evidence_locations: Vec<serde_json::Value> = cve
                        .evidence
                        .iter()
                        .map(|loc| {
                            sarif_evidence_location(
                                loc,
                                data.root_path.as_deref(),
                            )
                        })
                        .collect();
                    let declaration_locations = sarif_declaration_locations(
                        &finding.declarations,
                        data.root_path.as_deref(),
                    );
                    let manifest_fallback: Vec<serde_json::Value> =
                        manifest_uris
                            .iter()
                            .map(|uri| {
                                sarif_physical_location(uri, None, None)
                            })
                            .collect();
                    let has_evidence = !evidence_locations.is_empty();
                    let has_declarations = !declaration_locations.is_empty();
                    let locations = if has_evidence {
                        evidence_locations.clone()
                    } else if has_declarations {
                        declaration_locations.clone()
                    } else {
                        manifest_fallback.clone()
                    };
                    let related_locations = if has_evidence {
                        if has_declarations {
                            declaration_locations
                        } else {
                            manifest_fallback
                        }
                    } else {
                        Vec::new()
                    };
                    let mut result = serde_json::json!({
                        "ruleId": cve.id,
                        "level": severity_level_sarif(severity),
                        "message": { "text": cve.description },
                        "properties": {
                            "package": finding.package.name,
                            "version": finding.package.version,
                            "severity": severity.as_str(),
                            "manifest_paths": manifest_uris
                        }
                    });
                    if let Some(reachable) = cve.reachable {
                        result["properties"]["reachable"] =
                            serde_json::json!(reachable);
                    }
                    if !cve.advisory_symbols.is_empty() {
                        result["properties"]["advisory_symbols"] =
                            serde_json::json!(cve.advisory_symbols);
                    }
                    if let Some(ref usage) = cve.symbol_usage {
                        result["properties"]["symbol_usage"] =
                            serde_json::json!(usage);
                    }
                    if !cve.evidence.is_empty() {
                        let evidence_json: Vec<serde_json::Value> = cve
                            .evidence
                            .iter()
                            .map(|loc| {
                                serde_json::json!({
                                    "path": loc.path,
                                    "start_line": loc.start_line,
                                    "symbol": loc.symbol
                                })
                            })
                            .collect();
                        result["properties"]["evidence"] =
                            serde_json::json!(evidence_json);
                    }
                    if !locations.is_empty() {
                        result["locations"] =
                            serde_json::Value::Array(locations);
                    }
                    if has_evidence && !related_locations.is_empty() {
                        result["relatedLocations"] =
                            serde_json::Value::Array(related_locations);
                    }
                    result
                })
            })
            .collect();
        let rules: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|f| f.cves.iter().map(|(cve, _)| cve.id.clone()))
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
        let mut run_obj = serde_json::json!({
            "tool": {
                "driver": {
                    "name": "vlz",
                    "informationUri": VLZ_REPOSITORY_URL,
                    "rules": rules
                }
            },
            "results": results
        });
        if let Some(ref pid) = data.project_id {
            run_obj["properties"] = serde_json::json!({ "project_id": pid });
        }
        if !data.manifest_coverage.is_empty() {
            let props = run_obj
                .get_mut("properties")
                .and_then(|v| v.as_object_mut());
            let coverage = manifest_coverage_json_array(
                &data.manifest_coverage,
                data.root_path.as_deref(),
            );
            match props {
                Some(obj) => {
                    obj.insert(
                        "manifest_coverage".to_string(),
                        serde_json::Value::Array(coverage),
                    );
                }
                None => {
                    run_obj["properties"] = serde_json::json!({
                        "manifest_coverage": coverage
                    });
                }
            }
        }
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [run_obj]
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

/// PURL type for SBOM output from a package ecosystem (SEC-019 CycloneDX 1.6).
fn purl_type_for_ecosystem(ecosystem: Option<&str>) -> &'static str {
    match ecosystem {
        Some(CRATES_IO_ECOSYSTEM) => "cargo",
        Some(GO_ECOSYSTEM) => "golang",
        Some(PYPI_ECOSYSTEM) | None => "pypi",
        _ => "pypi",
    }
}

/// PURL for a resolved package (SEC-019 CycloneDX 1.6, SPDX 3.0).
fn purl_for_package(pkg: &Package) -> String {
    let purl_type = purl_type_for_ecosystem(pkg.ecosystem.as_deref());
    format!("pkg:{}/{}@{}", purl_type, pkg.name, pkg.version)
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
                data.findings.iter().map(|f| &f.package).collect::<Vec<_>>()
            });
        let components: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                let bom_ref = purl_for_package(p);
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
            .flat_map(|finding| {
                finding.cves.iter().map(|(cve, severity)| {
                    let bom_ref = purl_for_package(&finding.package);
                    let manifest_paths: Vec<String> = finding
                        .manifest_paths
                        .iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                    let mut vuln = serde_json::json!({
                        "id": cve.id,
                        "description": cve.description,
                        "affects": [{ "ref": bom_ref }],
                        "properties": [{ "name": "vlz:manifest_paths", "value": manifest_paths.join("; ") }]
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
        let mut metadata = serde_json::json!({
            "timestamp": format_timestamp_rfc3339(),
            "tools": [{ "name": "vlz", "vendor": "verilyze" }]
        });
        if let Some(ref pid) = data.project_id {
            metadata["properties"] = serde_json::json!([{
                "name": "vlz:project_id",
                "value": pid
            }]);
        }
        let bom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": metadata,
            "components": components,
            "vulnerabilities": vulnerabilities
        });
        let s = serde_json::to_string_pretty(&bom)?;
        writeln!(w, "{}", s).map_err(ReportError::Io)?;
        w.flush()?;
        Ok(())
    }
}

/// SPDX ID prefix for a package ecosystem (SEC-019 SPDX 3.0).
fn spdx_id_prefix_for_ecosystem(ecosystem: Option<&str>) -> &'static str {
    match purl_type_for_ecosystem(ecosystem) {
        "cargo" => "pkg-cargo",
        "golang" => "pkg-golang",
        _ => "pkg-pypi",
    }
}

/// SPDX ID for a package (SEC-019 SPDX 3.0).
fn spdx_id_pkg(pkg: &Package) -> String {
    let prefix = spdx_id_prefix_for_ecosystem(pkg.ecosystem.as_deref());
    format!(
        "urn:spdx.dev:{}-{}-{}",
        prefix,
        pkg.name.replace(['.', '-', '_'], "-"),
        pkg.version.replace(['.', '-', '_'], "-")
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
                data.findings.iter().map(|f| &f.package).collect::<Vec<_>>()
            });
        let pkg_elements: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                let sid = spdx_id_pkg(p);
                serde_json::json!({
                    "@type": "Package",
                    "spdxId": sid,
                    "name": p.name,
                    "versionInfo": p.version,
                    "packageUrl": purl_for_package(p)
                })
            })
            .collect();
        let vuln_elements: Vec<serde_json::Value> = data
            .findings
            .iter()
            .flat_map(|finding| {
                finding.cves.iter().map(|(cve, _)| {
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
            .flat_map(|finding| {
                finding.cves.iter().map(|(cve, _)| {
                    let mut rel = serde_json::json!({
                        "@type": "Relationship",
                        "relationshipType": "hasAssociatedVulnerability",
                        "from": spdx_id_pkg(&finding.package),
                        "to": [spdx_id_vuln(&cve.id)]
                    });
                    if !finding.manifest_paths.is_empty() {
                        let paths: Vec<String> = finding
                            .manifest_paths
                            .iter()
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect();
                        rel["annotations"] = serde_json::json!([{
                            "annotationType": "review",
                            "annotator": { "annotatorType": "tool", "name": "vlz" },
                            "annotationDate": format_timestamp_rfc3339(),
                            "comment": format!("Manifest(s): {}", paths.join("; "))
                        }]);
                    }
                    rel
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
        let mut spdx = serde_json::json!({
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
        if let Some(ref pid) = data.project_id {
            spdx["projectId"] = serde_json::json!(pid);
        }
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
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
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
            advisory_symbols: Vec::new(),
            evidence: Vec::new(),
            symbol_usage: None,
        };
        ReportData {
            findings: vec![Finding {
                package: pkg,
                manifest_paths: vec![PathBuf::from("Cargo.toml")],
                declarations: Vec::new(),
                cves: vec![(cve, Severity::High)],
            }],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        }
    }

    fn sample_report_data_with_manifest_coverage() -> ReportData {
        ReportData {
            findings: vec![],
            all_packages: None,
            project_id: None,
            root_path: Some(PathBuf::from("/root")),
            manifest_coverage: vec![
                ManifestCoverageEntry {
                    path: PathBuf::from("/root/good/requirements.txt"),
                    language: "python".to_string(),
                    status: ManifestScanStatus::ScannedTransitive,
                    direct_only_reason: None,
                    error: None,
                },
                ManifestCoverageEntry {
                    path: PathBuf::from("/root/broken/requirements.txt"),
                    language: "python".to_string(),
                    status: ManifestScanStatus::FailedResolution,
                    direct_only_reason: None,
                    error: Some("resolve failed".to_string()),
                },
            ],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        }
    }

    fn sample_report_data_with_all_packages() -> ReportData {
        let pkg_foo = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
        };
        let pkg_bar = Package {
            name: "bar".to_string(),
            version: "2.0".to_string(),
            ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
        };
        let cve = CveRecord {
            id: "CVE-2023-1234".to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "A bug".to_string(),
            reachable: None,
            advisory_symbols: Vec::new(),
            evidence: Vec::new(),
            symbol_usage: None,
        };
        ReportData {
            findings: vec![Finding {
                package: pkg_foo.clone(),
                manifest_paths: vec![PathBuf::from("Cargo.toml")],
                declarations: Vec::new(),
                cves: vec![(cve, Severity::High)],
            }],
            all_packages: Some(vec![pkg_foo, pkg_bar]),
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
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
        assert!(out.contains(NO_VULNERABILITIES_FOUND_MESSAGE));
    }

    #[tokio::test]
    async fn default_reporter_incomplete_scan_empty_findings() {
        let data = sample_report_data_with_manifest_coverage();
        let mut buf = Vec::new();
        DefaultReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains(SCAN_INCOMPLETE_MESSAGE));
        assert!(!out.contains(NO_VULNERABILITIES_FOUND_MESSAGE));
        assert!(!out.contains(DEGRADED_COVERAGE_NO_VULNERABILITIES_MESSAGE));
    }

    #[test]
    fn empty_findings_message_degraded_coverage() {
        let data = ReportData {
            findings: vec![],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![ManifestCoverageEntry {
                path: PathBuf::from("pyproject.toml"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedDirectOnly,
                direct_only_reason: Some("offline mode".to_string()),
                error: None,
            }],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        assert!(data.has_degraded_coverage());
        assert!(!data.is_analysis_incomplete());
        assert_eq!(
            data.empty_findings_message(),
            DEGRADED_COVERAGE_NO_VULNERABILITIES_MESSAGE
        );
    }

    #[test]
    fn empty_findings_message_incomplete_overrides_degraded() {
        let data = ReportData {
            findings: vec![],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![
                ManifestCoverageEntry {
                    path: PathBuf::from("pyproject.toml"),
                    language: "python".to_string(),
                    status: ManifestScanStatus::ScannedDirectOnly,
                    direct_only_reason: Some("offline mode".to_string()),
                    error: None,
                },
                ManifestCoverageEntry {
                    path: PathBuf::from("broken.txt"),
                    language: "python".to_string(),
                    status: ManifestScanStatus::FailedResolution,
                    direct_only_reason: None,
                    error: Some("err".to_string()),
                },
            ],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        assert!(data.has_degraded_coverage());
        assert!(data.is_analysis_incomplete());
        assert_eq!(data.empty_findings_message(), SCAN_INCOMPLETE_MESSAGE);
    }

    #[tokio::test]
    async fn default_reporter_degraded_coverage_empty_findings() {
        let data = ReportData {
            findings: vec![],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![ManifestCoverageEntry {
                path: PathBuf::from("requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedDirectOnly,
                direct_only_reason: Some(
                    "transitive resolution failed; direct-only fallback enabled"
                        .to_string(),
                ),
                error: None,
            }],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        let mut buf = Vec::new();
        DefaultReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains(DEGRADED_COVERAGE_NO_VULNERABILITIES_MESSAGE));
        assert!(!out.contains(NO_VULNERABILITIES_FOUND_MESSAGE));
        assert!(!out.contains(SCAN_INCOMPLETE_MESSAGE));
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
        assert!(out.contains("Manifest(s)"));
        assert!(out.contains("Cargo.toml"));
    }

    #[test]
    fn manifest_coverage_needs_section_true_for_failures() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("requirements.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::FailedResolution,
            direct_only_reason: None,
            error: Some("err".to_string()),
        }];
        assert!(manifest_coverage_needs_section(&coverage));
    }

    #[test]
    fn manifest_coverage_needs_section_false_for_transitive_only() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("requirements.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::ScannedTransitive,
            direct_only_reason: None,
            error: None,
        }];
        assert!(!manifest_coverage_needs_section(&coverage));
    }

    #[tokio::test]
    async fn json_reporter_includes_schema_reference_doc005() {
        let data = sample_report_data_empty();
        let mut buf = Vec::new();
        JsonReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        assert_eq!(
            parsed.get("$schema").and_then(|v| v.as_str()),
            Some(REPORT_JSON_SCHEMA_ID)
        );
    }

    #[tokio::test]
    async fn json_reporter_includes_manifest_coverage() {
        let data = sample_report_data_with_manifest_coverage();
        let mut buf = Vec::new();
        JsonReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let coverage = parsed
            .get("manifest_coverage")
            .expect("manifest_coverage")
            .as_array()
            .expect("array");
        assert_eq!(coverage.len(), 2);
        assert_eq!(
            coverage[1].get("status").unwrap(),
            MANIFEST_STATUS_FAILED_RESOLUTION
        );
        assert_eq!(
            coverage[1].get("path").unwrap(),
            "broken/requirements.txt"
        );
    }

    #[tokio::test]
    async fn default_reporter_includes_manifest_coverage_section() {
        let data = sample_report_data_with_manifest_coverage();
        let mut buf = Vec::new();
        DefaultReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Manifest coverage:"));
        assert!(out.contains("failed_resolution"));
        assert!(out.contains("broken/requirements.txt"));
    }

    #[tokio::test]
    async fn sarif_reporter_includes_manifest_coverage_in_properties() {
        let data = sample_report_data_with_manifest_coverage();
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let props = parsed["runs"][0]["properties"]
            .get("manifest_coverage")
            .expect("manifest_coverage in properties")
            .as_array()
            .expect("array");
        assert_eq!(props.len(), 2);
    }

    #[tokio::test]
    async fn html_reporter_includes_manifest_coverage_table() {
        let data = sample_report_data_with_manifest_coverage();
        let mut buf = Vec::new();
        HtmlReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Manifest coverage"));
        assert!(out.contains("failed_resolution"));
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
        let manifest_paths = findings[0]
            .get("manifest_paths")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(manifest_paths.len(), 1);
        assert_eq!(manifest_paths[0], "Cargo.toml");
    }

    #[tokio::test]
    async fn json_reporter_includes_project_id_when_provided_fr015a() {
        let mut data = sample_report_data_one_finding();
        data.project_id = Some("myproj".to_string());
        let mut buf = Vec::new();
        JsonReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed.get("project_id").unwrap(), "myproj");
    }

    #[tokio::test]
    async fn json_reporter_omits_project_id_when_not_provided_fr015a() {
        let data = sample_report_data_one_finding();
        let mut buf = Vec::new();
        JsonReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap();
        assert!(parsed.get("project_id").is_none());
    }

    #[tokio::test]
    async fn default_reporter_includes_project_id_when_provided_fr015a() {
        let mut data = sample_report_data_empty();
        data.project_id = Some("myproj".to_string());
        let mut buf = Vec::new();
        DefaultReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Project: myproj"));
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
            advisory_symbols: Vec::new(),
            evidence: Vec::new(),
            symbol_usage: None,
        };
        let data = ReportData {
            findings: vec![Finding {
                package: pkg,
                manifest_paths: vec![PathBuf::from("pyproject.toml")],
                declarations: Vec::new(),
                cves: vec![(cve, Severity::Medium)],
            }],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
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

    #[test]
    fn sarif_percent_encodes_spaces_in_path() {
        assert_eq!(
            sarif_percent_encode_path("src/my file.rs"),
            "src/my%20file.rs"
        );
    }

    #[tokio::test]
    async fn sarif_reporter_uses_declarations_as_primary_when_no_evidence() {
        use vlz_db::{DeclarationKind, PackageDeclarationLocation};
        let pkg = Package {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
        };
        let cve = CveRecord {
            id: "CVE-DECL".to_string(),
            cvss_score: Some(5.0),
            cvss_version: Some(CvssVersion::V3),
            description: "Declaration only".to_string(),
            reachable: None,
            advisory_symbols: Vec::new(),
            evidence: Vec::new(),
            symbol_usage: None,
        };
        let data = ReportData {
            findings: vec![Finding {
                package: pkg,
                manifest_paths: vec![PathBuf::from("pyproject.toml")],
                declarations: vec![
                    PackageDeclarationLocation::new(
                        "pyproject.toml",
                        8,
                        None,
                        DeclarationKind::Manifest,
                    )
                    .unwrap(),
                ],
                cves: vec![(cve, Severity::Medium)],
            }],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let result = &parsed["runs"][0]["results"][0];
        let location = &result["locations"][0];
        assert_eq!(
            location["physicalLocation"]["region"]["startLine"].as_u64(),
            Some(8)
        );
        assert_eq!(
            location["properties"]["location_kind"].as_str(),
            Some("declaration")
        );
        assert!(result.get("relatedLocations").is_none());
    }

    #[tokio::test]
    async fn sarif_reporter_puts_declarations_in_related_when_evidence_present()
     {
        use vlz_db::{DeclarationKind, PackageDeclarationLocation};
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some(GO_ECOSYSTEM.to_string()),
        };
        let cve = CveRecord {
            id: "CVE-EVID".to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "Symbol usage".to_string(),
            reachable: Some(true),
            advisory_symbols: vec!["VulnFn".to_string()],
            evidence: vec![CveEvidenceLocation {
                path: "main.go".to_string(),
                start_line: 4,
                end_line: None,
                symbol: "VulnFn".to_string(),
            }],
            symbol_usage: Some("used".to_string()),
        };
        let data = ReportData {
            findings: vec![Finding {
                package: pkg,
                manifest_paths: vec![PathBuf::from("go.mod")],
                declarations: vec![
                    PackageDeclarationLocation::new(
                        "go.mod",
                        3,
                        None,
                        DeclarationKind::Manifest,
                    )
                    .unwrap(),
                ],
                cves: vec![(cve, Severity::High)],
            }],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let result = &parsed["runs"][0]["results"][0];
        let location = &result["locations"][0]["physicalLocation"];
        assert_eq!(
            location["artifactLocation"]["uri"].as_str(),
            Some("main.go")
        );
        let related = result["relatedLocations"]
            .as_array()
            .expect("relatedLocations");
        assert_eq!(related.len(), 1);
        assert_eq!(
            related[0]["physicalLocation"]["region"]["startLine"].as_u64(),
            Some(3)
        );
        assert_eq!(
            related[0]["properties"]["location_kind"].as_str(),
            Some("declaration")
        );
    }

    #[tokio::test]
    async fn sarif_reporter_uses_evidence_as_primary_location() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some(GO_ECOSYSTEM.to_string()),
        };
        let cve = CveRecord {
            id: "CVE-EVID".to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "Symbol usage".to_string(),
            reachable: Some(true),
            advisory_symbols: vec!["VulnFn".to_string()],
            evidence: vec![CveEvidenceLocation {
                path: "main.go".to_string(),
                start_line: 4,
                end_line: None,
                symbol: "VulnFn".to_string(),
            }],
            symbol_usage: Some("used".to_string()),
        };
        let data = ReportData {
            findings: vec![Finding {
                package: pkg,
                manifest_paths: vec![PathBuf::from("go.mod")],
                declarations: Vec::new(),
                cves: vec![(cve, Severity::High)],
            }],
            all_packages: None,
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        let mut buf = Vec::new();
        SarifReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let result = &parsed["runs"][0]["results"][0];
        let location = &result["locations"][0]["physicalLocation"];
        assert_eq!(
            location["artifactLocation"]["uri"].as_str(),
            Some("main.go")
        );
        assert_eq!(location["region"]["startLine"].as_u64(), Some(4));
        let related = result["relatedLocations"]
            .as_array()
            .expect("relatedLocations");
        assert_eq!(related.len(), 1);
        assert_eq!(
            related[0]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
            Some("go.mod")
        );
        assert_eq!(
            result["properties"]["symbol_usage"].as_str(),
            Some("used")
        );
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
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
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
        let purls: Vec<&str> = components
            .iter()
            .map(|c| c.get("purl").unwrap().as_str().unwrap())
            .collect();
        assert!(purls.contains(&"pkg:cargo/foo@1.0"));
        assert!(purls.contains(&"pkg:pypi/bar@2.0"));
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
        assert_eq!(affects[0].get("ref").unwrap(), "pkg:cargo/foo@1.0");
    }

    #[tokio::test]
    async fn cyclonedx_reporter_collision_names_use_cargo_purls() {
        let collision_crates = [
            ("ryu", "1.0.23"),
            ("h2", "0.4.13"),
            ("idna", "1.1.0"),
            ("wiremock", "0.6.5"),
        ];
        let packages: Vec<Package> = collision_crates
            .iter()
            .map(|(name, version)| Package {
                name: (*name).to_string(),
                version: (*version).to_string(),
                ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
            })
            .collect();
        let data = ReportData {
            findings: vec![],
            all_packages: Some(packages),
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        let mut buf = Vec::new();
        CycloneDxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let components = parsed.get("components").unwrap().as_array().unwrap();
        for (name, version) in collision_crates {
            let expected = format!("pkg:cargo/{}@{}", name, version);
            assert!(
                components.iter().any(|c| {
                    c.get("purl").and_then(|p| p.as_str())
                        == Some(expected.as_str())
                }),
                "expected cargo PURL for {name}, not pkg:pypi"
            );
        }
    }

    #[tokio::test]
    async fn cyclonedx_reporter_go_packages_use_golang_purls() {
        let pkg = Package {
            name: "github.com/example/mod".to_string(),
            version: "v1.2.3".to_string(),
            ecosystem: Some(GO_ECOSYSTEM.to_string()),
        };
        let data = ReportData {
            findings: vec![],
            all_packages: Some(vec![pkg]),
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
        };
        let mut buf = Vec::new();
        CycloneDxReporter::new()
            .render_to_writer(&data, &mut buf)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim())
                .unwrap();
        let purl = parsed["components"][0]["purl"].as_str().unwrap();
        assert_eq!(purl, "pkg:golang/github.com/example/mod@v1.2.3");
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
            project_id: None,
            root_path: None,
            manifest_coverage: vec![],
            offline_cache_miss: false,
            provider_fetch_failed: false,
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
        let pkg_urls: Vec<&str> = elements
            .iter()
            .filter_map(|e| {
                if e.get("@type").and_then(|t| t.as_str()) == Some("Package") {
                    e.get("packageUrl").and_then(|u| u.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(pkg_urls.contains(&"pkg:cargo/foo@1.0"));
        assert!(pkg_urls.contains(&"pkg:pypi/bar@2.0"));
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
