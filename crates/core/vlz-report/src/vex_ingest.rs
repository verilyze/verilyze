// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! VEX consume: OpenVEX and CycloneDX analysis ingest (FR-049).
//!
//! Ephemeral suppress input for scans. Does not rewrite `vlz-ignore.json`.
//! Unknown statuses and untrusted documents never silently drop findings.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{OPENVEX_CONTEXT, VexJustification, VexStatus};
use vlz_db::normalize_vuln_id;

/// Known OpenVEX `@context` URLs accepted for ingest.
pub const OPENVEX_INGEST_CONTEXTS: &[&str] = &[
    OPENVEX_CONTEXT,
    "https://openvex.dev/ns",
    "https://openvex.dev/ns/v0.2.0",
];

/// Document kind detected for an ingest path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexIngestKind {
    OpenVex,
    CycloneDxAnalysis,
}

/// Source document for one ingested statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexIngestSource {
    OpenVex,
    CycloneDx,
}

/// Parsed ingest status after allowlist mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestStatus {
    NotAffected,
    Fixed,
    Affected,
    UnderInvestigation,
    /// Present in the document but not a suppressible / known status.
    Unknown,
}

impl IngestStatus {
    /// True when this status may suppress a finding under FR-049.
    pub fn may_suppress(self) -> bool {
        matches!(self, Self::NotAffected | Self::Fixed)
    }
}

/// One statement extracted from an OpenVEX or CycloneDX analysis document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedVexStatement {
    pub vuln_id: String,
    pub purl: Option<String>,
    pub product_ids: Vec<String>,
    pub status: IngestStatus,
    pub justification: Option<String>,
    pub detail: Option<String>,
    pub source: VexIngestSource,
    pub source_path: PathBuf,
    /// False when the document is unsigned and policy rejects unsigned.
    pub trusted: bool,
}

/// Result of parsing one VEX ingest file.
#[derive(Debug, Clone, Default)]
pub struct VexIngestParseResult {
    pub statements: Vec<IngestedVexStatement>,
    pub warnings: Vec<String>,
    pub kind: Option<VexIngestKind>,
}

/// Policy for applying ingested statements (FR-049).
#[derive(Debug, Clone)]
pub struct VexIngestPolicy {
    /// When false, unsigned documents never suppress.
    pub allow_unsigned: bool,
    /// Optional product id filter (`[vex].product_id`).
    pub product_id: Option<String>,
}

impl Default for VexIngestPolicy {
    fn default() -> Self {
        Self {
            allow_unsigned: true,
            product_id: None,
        }
    }
}

/// Error opening or decoding a configured `--from-vex` path.
#[derive(Debug, thiserror::Error)]
pub enum VexIngestError {
    #[error("failed to read VEX ingest file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("VEX ingest file {path} is not valid JSON: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Parse a VEX ingest document from bytes (OpenVEX or CycloneDX analysis).
pub fn parse_vex_ingest_bytes(
    bytes: &[u8],
    path: &Path,
    policy: &VexIngestPolicy,
) -> Result<VexIngestParseResult, VexIngestError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|source| {
        VexIngestError::Json {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(parse_vex_ingest_value(&value, path, policy))
}

/// Parse from a filesystem path.
pub fn parse_vex_ingest_file(
    path: &Path,
    policy: &VexIngestPolicy,
) -> Result<VexIngestParseResult, VexIngestError> {
    let bytes = std::fs::read(path).map_err(|source| VexIngestError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_vex_ingest_bytes(&bytes, path, policy)
}

/// Detect document kind and extract statements.
pub fn parse_vex_ingest_value(
    value: &Value,
    path: &Path,
    policy: &VexIngestPolicy,
) -> VexIngestParseResult {
    let mut out = VexIngestParseResult::default();
    let trusted = policy.allow_unsigned;
    if is_openvex_document(value) {
        out.kind = Some(VexIngestKind::OpenVex);
        parse_openvex_statements(value, path, trusted, &mut out);
    } else if is_cyclonedx_with_vulns(value) {
        out.kind = Some(VexIngestKind::CycloneDxAnalysis);
        parse_cyclonedx_analysis(value, path, trusted, &mut out);
    } else {
        out.warnings.push(format!(
            "VEX ingest {}: unrecognized document (need OpenVEX @context or \
             CycloneDX bomFormat with vulnerabilities); findings not suppressed",
            path.display()
        ));
    }
    out
}

/// Collect vuln ids that should suppress findings under policy.
pub fn suppress_vuln_ids(
    statements: &[IngestedVexStatement],
    policy: &VexIngestPolicy,
    warnings: &mut Vec<String>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for stmt in statements {
        if !stmt.trusted {
            warnings.push(format!(
                "VEX ingest {}: unsigned statement for {} ignored \
                 (allow_unsigned_vex is false)",
                stmt.source_path.display(),
                stmt.vuln_id
            ));
            continue;
        }
        if !stmt.status.may_suppress() {
            if stmt.status == IngestStatus::Unknown {
                warnings.push(format!(
                    "VEX ingest {}: unknown status for {}; finding kept",
                    stmt.source_path.display(),
                    stmt.vuln_id
                ));
            }
            continue;
        }
        if let Some(want) = policy.product_id.as_deref() {
            if !stmt.product_ids.is_empty()
                && !stmt
                    .product_ids
                    .iter()
                    .any(|p| product_id_matches(p, want))
            {
                warnings.push(format!(
                    "VEX ingest {}: product mismatch for {} (want {want}); \
                     finding kept",
                    stmt.source_path.display(),
                    stmt.vuln_id
                ));
                continue;
            }
        }
        let key = normalize_vuln_id(&stmt.vuln_id);
        if !key.is_empty() {
            out.insert(key);
        }
    }
    out
}

/// Merge ignore-db keys with ingested suppress keys (ignore wins on conflict
/// only in the sense that both suppress; ignore justification is preferred
/// later when generating VEX).
pub fn merge_suppress_keys(
    ignore_keys: &HashSet<String>,
    ingested: HashSet<String>,
) -> HashSet<String> {
    let mut out = ignore_keys.clone();
    out.extend(ingested);
    out
}

fn is_openvex_document(value: &Value) -> bool {
    let Some(ctx) = value.get("@context") else {
        return false;
    };
    match ctx {
        Value::String(s) => openvex_context_ok(s),
        Value::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(openvex_context_ok)),
        _ => false,
    }
}

fn openvex_context_ok(s: &str) -> bool {
    let s = s.trim();
    OPENVEX_INGEST_CONTEXTS.iter().any(|c| s == *c)
        || s.starts_with("https://openvex.dev/ns")
}

fn is_cyclonedx_with_vulns(value: &Value) -> bool {
    value
        .get("bomFormat")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("CycloneDX"))
        && value.get("vulnerabilities").is_some()
}

fn parse_openvex_statements(
    value: &Value,
    path: &Path,
    trusted: bool,
    out: &mut VexIngestParseResult,
) {
    let Some(stmts) = value.get("statements").and_then(|v| v.as_array())
    else {
        out.warnings.push(format!(
            "VEX ingest {}: OpenVEX document has no statements array",
            path.display()
        ));
        return;
    };
    for stmt in stmts {
        let Some(vuln_id) = openvex_vuln_name(stmt) else {
            out.warnings.push(format!(
                "VEX ingest {}: statement missing vulnerability.name; skipped",
                path.display()
            ));
            continue;
        };
        let status_raw =
            stmt.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let status = map_openvex_status(status_raw);
        if status == IngestStatus::Unknown && !status_raw.is_empty() {
            out.warnings.push(format!(
                "VEX ingest {}: unknown OpenVEX status `{status_raw}` for \
                 {vuln_id}; finding kept",
                path.display()
            ));
        }
        let (product_ids, purls) = openvex_products(stmt);
        let purl = purls.into_iter().next();
        let justification = stmt
            .get("justification")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let detail = stmt
            .get("impact_statement")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.statements.push(IngestedVexStatement {
            vuln_id,
            purl,
            product_ids,
            status,
            justification,
            detail,
            source: VexIngestSource::OpenVex,
            source_path: path.to_path_buf(),
            trusted,
        });
    }
}

fn openvex_vuln_name(stmt: &Value) -> Option<String> {
    let v = stmt.get("vulnerability")?;
    if let Some(name) = v.get("name").and_then(|x| x.as_str()) {
        let name = name.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    None
}

fn openvex_products(stmt: &Value) -> (Vec<String>, Vec<String>) {
    let mut products = Vec::new();
    let mut purls = Vec::new();
    let Some(arr) = stmt.get("products").and_then(|v| v.as_array()) else {
        return (products, purls);
    };
    for product in arr {
        if let Some(id) = product.get("@id").and_then(|v| v.as_str()) {
            products.push(id.to_string());
        }
        if let Some(subs) =
            product.get("subcomponents").and_then(|v| v.as_array())
        {
            for sub in subs {
                if let Some(id) = sub.get("@id").and_then(|v| v.as_str()) {
                    if id.starts_with("pkg:") {
                        purls.push(id.to_string());
                    } else {
                        products.push(id.to_string());
                    }
                }
            }
        }
    }
    (products, purls)
}

fn map_openvex_status(raw: &str) -> IngestStatus {
    match raw.trim() {
        "not_affected" => IngestStatus::NotAffected,
        "fixed" => IngestStatus::Fixed,
        "affected" => IngestStatus::Affected,
        "under_investigation" => IngestStatus::UnderInvestigation,
        _ => IngestStatus::Unknown,
    }
}

fn parse_cyclonedx_analysis(
    value: &Value,
    path: &Path,
    trusted: bool,
    out: &mut VexIngestParseResult,
) {
    let Some(vulns) = value.get("vulnerabilities").and_then(|v| v.as_array())
    else {
        return;
    };
    for vuln in vulns {
        let Some(vuln_id) = vuln
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
        else {
            out.warnings.push(format!(
                "VEX ingest {}: CycloneDX vulnerability missing id; skipped",
                path.display()
            ));
            continue;
        };
        let Some(analysis) = vuln.get("analysis") else {
            // Inventory-only vulnerability rows are not VEX suppress input.
            continue;
        };
        let state =
            analysis.get("state").and_then(|v| v.as_str()).unwrap_or("");
        let status = map_cyclonedx_state(state);
        if status == IngestStatus::Unknown && !state.is_empty() {
            out.warnings.push(format!(
                "VEX ingest {}: unknown CycloneDX analysis.state `{state}` \
                 for {vuln_id}; finding kept",
                path.display()
            ));
        }
        let justification = analysis
            .get("justification")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let detail = analysis
            .get("detail")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let mut purls = Vec::new();
        if let Some(affects) = vuln.get("affects").and_then(|v| v.as_array()) {
            for a in affects {
                if let Some(r) = a.get("ref").and_then(|v| v.as_str())
                    && r.starts_with("pkg:")
                {
                    purls.push(r.to_string());
                }
            }
        }
        let purl = purls.into_iter().next();
        out.statements.push(IngestedVexStatement {
            vuln_id,
            purl,
            product_ids: Vec::new(),
            status,
            justification,
            detail,
            source: VexIngestSource::CycloneDx,
            source_path: path.to_path_buf(),
            trusted,
        });
    }
}

fn map_cyclonedx_state(raw: &str) -> IngestStatus {
    match raw.trim() {
        "not_affected" | "false_positive" => IngestStatus::NotAffected,
        "resolved" | "resolved_with_pedigree" => IngestStatus::Fixed,
        "exploitable" => IngestStatus::Affected,
        "in_triage" => IngestStatus::UnderInvestigation,
        _ => IngestStatus::Unknown,
    }
}

fn product_id_matches(documented: &str, want: &str) -> bool {
    documented == want || documented.trim() == want.trim()
}

/// Map ingest justification string onto generate vocabulary when possible.
pub fn ingest_justification_as_vex(
    raw: Option<&str>,
) -> Option<VexJustification> {
    raw.and_then(VexJustification::parse).or_else(|| {
        // CycloneDX analysis.justification values
        match raw? {
            "code_not_present" => {
                Some(VexJustification::VulnerableCodeNotPresent)
            }
            "code_not_reachable" => {
                Some(VexJustification::VulnerableCodeNotInExecutePath)
            }
            "requires_dependency" => {
                Some(VexJustification::ComponentNotPresent)
            }
            "protected_at_perimeter" => Some(
                VexJustification::VulnerableCodeCannotBeControlledByAdversary,
            ),
            "protected_by_mitigating_control" => {
                Some(VexJustification::InlineMitigationsAlreadyExist)
            }
            _ => None,
        }
    })
}

/// Map ingest status to generate VexStatus for emit enrichment.
pub fn ingest_status_as_vex(status: IngestStatus) -> Option<VexStatus> {
    match status {
        IngestStatus::NotAffected | IngestStatus::Fixed => {
            Some(VexStatus::NotAffected)
        }
        IngestStatus::Affected => Some(VexStatus::Affected),
        IngestStatus::UnderInvestigation => {
            Some(VexStatus::UnderInvestigation)
        }
        IngestStatus::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn openvex_not_affected_suppresses() {
        let doc = serde_json::json!({
            "@context": OPENVEX_CONTEXT,
            "author": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": 1,
            "statements": [{
                "vulnerability": { "name": "CVE-2024-1" },
                "products": [{
                    "@id": "pkg:generic/app@1",
                    "subcomponents": [{ "@id": "pkg:npm/lodash@4.17.21" }]
                }],
                "status": "not_affected",
                "justification": "vulnerable_code_not_present"
            }]
        });
        let policy = VexIngestPolicy::default();
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("a.openvex.json"), &policy);
        assert_eq!(parsed.kind, Some(VexIngestKind::OpenVex));
        assert_eq!(parsed.statements.len(), 1);
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.contains("CVE-2024-1"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn openvex_unknown_status_does_not_suppress() {
        let doc = serde_json::json!({
            "@context": OPENVEX_CONTEXT,
            "statements": [{
                "vulnerability": { "name": "CVE-2024-2" },
                "status": "not-a-real-status"
            }]
        });
        let policy = VexIngestPolicy::default();
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("b.openvex.json"), &policy);
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn openvex_fixed_suppresses_but_upgrade_plans_are_irrelevant() {
        let doc = serde_json::json!({
            "@context": OPENVEX_CONTEXT,
            "statements": [{
                "vulnerability": { "name": "CVE-2024-3" },
                "status": "fixed"
            }]
        });
        let policy = VexIngestPolicy::default();
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("c.openvex.json"), &policy);
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.contains("CVE-2024-3"));
    }

    #[test]
    fn cyclonedx_analysis_not_affected_suppresses() {
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "vulnerabilities": [{
                "id": "CVE-2024-4",
                "analysis": {
                    "state": "not_affected",
                    "justification": "code_not_present",
                    "detail": "triaged"
                },
                "affects": [{ "ref": "pkg:npm/left-pad@1.0.0" }]
            }]
        });
        let policy = VexIngestPolicy::default();
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("bom.cdx.json"), &policy);
        assert_eq!(parsed.kind, Some(VexIngestKind::CycloneDxAnalysis));
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.contains("CVE-2024-4"));
    }

    #[test]
    fn cyclonedx_without_analysis_does_not_suppress() {
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [{ "id": "CVE-2024-5" }]
        });
        let policy = VexIngestPolicy::default();
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("inv.cdx.json"), &policy);
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.is_empty());
    }

    #[test]
    fn unsigned_rejected_when_disallowed() {
        let doc = serde_json::json!({
            "@context": OPENVEX_CONTEXT,
            "statements": [{
                "vulnerability": { "name": "CVE-2024-6" },
                "status": "not_affected"
            }]
        });
        let policy = VexIngestPolicy {
            allow_unsigned: false,
            product_id: None,
        };
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("u.openvex.json"), &policy);
        assert!(!parsed.statements[0].trusted);
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn product_filter_keeps_mismatched_findings() {
        let doc = serde_json::json!({
            "@context": OPENVEX_CONTEXT,
            "statements": [{
                "vulnerability": { "name": "CVE-2024-7" },
                "products": [{ "@id": "pkg:generic/other@1" }],
                "status": "not_affected"
            }]
        });
        let policy = VexIngestPolicy {
            allow_unsigned: true,
            product_id: Some("pkg:generic/app@1".into()),
        };
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("p.openvex.json"), &policy);
        let mut warnings = Vec::new();
        let keys =
            suppress_vuln_ids(&parsed.statements, &policy, &mut warnings);
        assert!(keys.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn unrecognized_document_warns_without_suppress() {
        let doc = serde_json::json!({ "hello": "world" });
        let policy = VexIngestPolicy::default();
        let parsed =
            parse_vex_ingest_value(&doc, Path::new("x.json"), &policy);
        assert!(parsed.kind.is_none());
        assert!(!parsed.warnings.is_empty());
        assert!(parsed.statements.is_empty());
    }

    #[test]
    fn merge_suppress_keys_unions_ignore_and_ingest() {
        let mut ignore = HashSet::new();
        ignore.insert("CVE-1".into());
        let mut ingest = HashSet::new();
        ingest.insert("CVE-2".into());
        let merged = merge_suppress_keys(&ignore, ingest);
        assert!(merged.contains("CVE-1"));
        assert!(merged.contains("CVE-2"));
    }

    #[test]
    fn missing_file_is_hard_error() {
        let policy = VexIngestPolicy::default();
        let err = parse_vex_ingest_file(
            Path::new("/no/such/vex-file-fr049.json"),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(err, VexIngestError::Io { .. }));
    }
}
