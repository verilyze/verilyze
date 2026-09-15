// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! VEX statement derivation and vocabulary (FR-044, FR-045).
//!
//! Generation only: CycloneDX `vulnerabilities[].analysis` and standalone
//! OpenVEX. Status derivation is pure (no I/O).

use crate::Finding;
use std::collections::HashMap;
use vlz_db::{FpEntry, purl_for_package};

/// OpenVEX `@context` for documents this crate emits.
pub const OPENVEX_CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

/// Default VEX author when not configured.
pub const DEFAULT_VEX_AUTHOR_NAME: &str = "verilyze";

/// CISA / OpenVEX justifications accepted by `vlz fp mark --justification`.
pub const CISA_JUSTIFICATIONS: &[&str] = &[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

/// VEX status values accepted by `vlz fp mark --status`.
pub const VEX_FP_STATUSES: &[&str] = &["not_affected"];

/// Default FP status when marking with VEX metadata.
pub const DEFAULT_FP_VEX_STATUS: &str = "not_affected";

/// Fallback CISA justification when an FP is marked without one.
pub const DEFAULT_FP_JUSTIFICATION: &str = "inline_mitigations_already_exist";

/// VEX statement status (OpenVEX / CISA vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexStatus {
    NotAffected,
    Affected,
    UnderInvestigation,
}

impl VexStatus {
    /// OpenVEX / CISA status string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Affected => "affected",
            Self::UnderInvestigation => "under_investigation",
        }
    }

    /// CycloneDX 1.6 `analysis.state` value.
    pub fn as_cyclonedx_state(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Affected => "exploitable",
            Self::UnderInvestigation => "in_triage",
        }
    }

    /// Parse a CISA/OpenVEX status string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "not_affected" => Some(Self::NotAffected),
            "affected" => Some(Self::Affected),
            "under_investigation" => Some(Self::UnderInvestigation),
            _ => None,
        }
    }
}

/// CISA minimum justification for `not_affected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

impl VexJustification {
    /// CISA / OpenVEX justification string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComponentNotPresent => "component_not_present",
            Self::VulnerableCodeNotPresent => "vulnerable_code_not_present",
            Self::VulnerableCodeNotInExecutePath => {
                "vulnerable_code_not_in_execute_path"
            }
            Self::VulnerableCodeCannotBeControlledByAdversary => {
                "vulnerable_code_cannot_be_controlled_by_adversary"
            }
            Self::InlineMitigationsAlreadyExist => {
                "inline_mitigations_already_exist"
            }
        }
    }

    /// Parse a CISA justification string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "component_not_present" => Some(Self::ComponentNotPresent),
            "vulnerable_code_not_present" => {
                Some(Self::VulnerableCodeNotPresent)
            }
            "vulnerable_code_not_in_execute_path" => {
                Some(Self::VulnerableCodeNotInExecutePath)
            }
            "vulnerable_code_cannot_be_controlled_by_adversary" => {
                Some(Self::VulnerableCodeCannotBeControlledByAdversary)
            }
            "inline_mitigations_already_exist" => {
                Some(Self::InlineMitigationsAlreadyExist)
            }
            _ => None,
        }
    }
}

/// Map CISA justification to CycloneDX 1.6 `analysis.justification`.
pub fn cisa_to_cyclonedx_justification(j: VexJustification) -> &'static str {
    match j {
        VexJustification::VulnerableCodeNotPresent => "code_not_present",
        VexJustification::VulnerableCodeNotInExecutePath => {
            "code_not_reachable"
        }
        // Distinct from inline mitigations: adversary cannot drive the
        // vulnerable code (perimeter / environmental control), not a local
        // inline mitigation already present in the component.
        VexJustification::VulnerableCodeCannotBeControlledByAdversary => {
            "protected_at_perimeter"
        }
        VexJustification::InlineMitigationsAlreadyExist => {
            "protected_by_mitigating_control"
        }
        VexJustification::ComponentNotPresent => "requires_dependency",
    }
}

/// Configuration snapshot for VEX generation (FR-046).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexConfig {
    pub product_id: Option<String>,
    pub author_name: String,
    pub author_namespace: Option<String>,
    /// When true, map `reachable: false` to `not_affected` (opt-in).
    pub reachability_not_affected: bool,
}

impl Default for VexConfig {
    fn default() -> Self {
        Self {
            product_id: None,
            author_name: DEFAULT_VEX_AUTHOR_NAME.to_string(),
            author_namespace: None,
            reachability_not_affected: false,
        }
    }
}

/// Treat blank / whitespace-only strings as unset (FR-046).
pub fn nonempty_optional_id(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

impl VexConfig {
    /// Drop blank `product_id` / `author_namespace` so empty config/env
    /// values cannot satisfy OpenVEX presence checks.
    pub fn normalize_optional_ids(&mut self) {
        self.product_id = nonempty_optional_id(self.product_id.take());
        self.author_namespace =
            nonempty_optional_id(self.author_namespace.take());
        let author = self.author_name.trim();
        if author.is_empty() {
            self.author_name = DEFAULT_VEX_AUTHOR_NAME.to_string();
        } else if author != self.author_name {
            self.author_name = author.to_string();
        }
    }

    /// Effective product id: configured product, else project id; blanks ignored.
    pub fn effective_product_id<'a>(
        &'a self,
        project_id: Option<&'a str>,
    ) -> Option<&'a str> {
        self.product_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| project_id.map(str::trim).filter(|s| !s.is_empty()))
    }
}

/// One VEX statement for a (package, CVE) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexStatement {
    pub cve_id: String,
    pub purl: String,
    pub status: VexStatus,
    pub justification: Option<VexJustification>,
    pub detail: Option<String>,
}

/// Derive VEX statements from active findings, suppressed FP findings, and config.
///
/// Precedence: FP mark > reachability > affected/in_triage.
/// Does not infer `fixed` from upgrade plans (prospective remediations).
pub fn derive_vex_statements(
    findings: &[Finding],
    suppressed_findings: &[Finding],
    fp_entries: &HashMap<String, FpEntry>,
    config: &VexConfig,
) -> Vec<VexStatement> {
    let mut out = Vec::new();
    for finding in suppressed_findings {
        for (cve, _) in &finding.cves {
            out.push(statement_for_suppressed(
                &finding.package,
                &cve.id,
                fp_entries.get(&cve.id),
            ));
        }
    }
    for finding in findings {
        for (cve, _) in &finding.cves {
            out.push(statement_for_active(&finding.package, cve, config));
        }
    }
    out
}

fn statement_for_suppressed(
    package: &vlz_db::Package,
    cve_id: &str,
    entry: Option<&FpEntry>,
) -> VexStatement {
    let justification = entry
        .and_then(|e| e.justification.as_deref())
        .and_then(VexJustification::parse)
        .or(Some(VexJustification::InlineMitigationsAlreadyExist));
    let status = entry
        .and_then(|e| e.status.as_deref())
        .and_then(VexStatus::parse)
        .unwrap_or(VexStatus::NotAffected);
    let detail = entry.and_then(|e| {
        e.detail.clone().or_else(|| {
            if e.comment.is_empty() {
                None
            } else {
                Some(e.comment.clone())
            }
        })
    });
    VexStatement {
        cve_id: cve_id.to_string(),
        purl: purl_for_package(package),
        status,
        justification: if status == VexStatus::NotAffected {
            justification
        } else {
            None
        },
        detail,
    }
}

fn statement_for_active(
    package: &vlz_db::Package,
    cve: &vlz_db::CveRecord,
    config: &VexConfig,
) -> VexStatement {
    let purl = purl_for_package(package);
    let detail = evidence_detail(cve);
    match cve.reachable {
        Some(false) if config.reachability_not_affected => VexStatement {
            cve_id: cve.id.clone(),
            purl,
            status: VexStatus::NotAffected,
            justification: Some(
                VexJustification::VulnerableCodeNotInExecutePath,
            ),
            detail,
        },
        Some(false) => VexStatement {
            cve_id: cve.id.clone(),
            purl,
            status: VexStatus::UnderInvestigation,
            justification: None,
            detail: Some(detail.unwrap_or_else(|| {
                "Reachability analysis did not find vulnerable code in \
                     the execute path; not asserted as not_affected \
                     (enable vex.reachability_not_affected to assert)."
                    .to_string()
            })),
        },
        Some(true) => VexStatement {
            cve_id: cve.id.clone(),
            purl,
            status: VexStatus::Affected,
            justification: None,
            detail,
        },
        None => VexStatement {
            cve_id: cve.id.clone(),
            purl,
            status: VexStatus::UnderInvestigation,
            justification: None,
            detail,
        },
    }
}

fn evidence_detail(cve: &vlz_db::CveRecord) -> Option<String> {
    if cve.evidence.is_empty() {
        return None;
    }
    let sites: Vec<String> = cve
        .evidence
        .iter()
        .take(5)
        .map(|e| format!("{}:{} ({})", e.path, e.start_line, e.symbol))
        .collect();
    Some(format!("Evidence: {}", sites.join("; ")))
}

/// Build CycloneDX `analysis` object for a statement (omits empty fields).
pub fn cyclonedx_analysis_for(statement: &VexStatement) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "state".to_string(),
        serde_json::Value::String(
            statement.status.as_cyclonedx_state().to_string(),
        ),
    );
    if statement.status == VexStatus::NotAffected
        && let Some(j) = statement.justification
    {
        obj.insert(
            "justification".to_string(),
            serde_json::Value::String(
                cisa_to_cyclonedx_justification(j).to_string(),
            ),
        );
    }
    if let Some(detail) = &statement.detail {
        obj.insert(
            "detail".to_string(),
            serde_json::Value::String(detail.clone()),
        );
    }
    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::{CveRecord, Package, Severity};
    use vlz_remediate::UpgradePlan;

    fn pkg() -> Package {
        Package {
            name: "demo".into(),
            version: "1.0.0".into(),
            ecosystem: Some("PyPI".into()),
        }
    }

    fn cve(id: &str, reachable: Option<bool>) -> CveRecord {
        CveRecord {
            id: id.into(),
            cvss_score: Some(7.5),
            cvss_version: None,
            description: "desc".into(),
            reachable,
            advisory_symbols: vec![],
            evidence: vec![],
            symbol_usage: None,
            affected_ranges: vec![],
        }
    }

    fn empty_upgrade_plan() -> UpgradePlan {
        UpgradePlan {
            minimal_fixed_version: vlz_remediate::MIN_FIXED_VERSION_UNKNOWN
                .to_string(),
            dependency_kind: vlz_remediate::DependencyKind::Unknown,
            apply_strategy: vlz_remediate::ApplyStrategy::Unavailable,
            confidence: vlz_remediate::UpgradePlanConfidence::Unknown,
        }
    }

    fn finding(cve: CveRecord) -> Finding {
        Finding {
            package: pkg(),
            manifest_paths: vec![],
            declarations: vec![],
            upgrade_plan: empty_upgrade_plan(),
            cves: vec![(cve, Severity::High)],
        }
    }

    #[test]
    fn cisa_justification_roundtrip_and_allowlist() {
        for s in CISA_JUSTIFICATIONS {
            let j = VexJustification::parse(s).expect(s);
            assert_eq!(j.as_str(), *s);
            assert!(!cisa_to_cyclonedx_justification(j).is_empty());
        }
        assert!(VexJustification::parse("not_a_real_reason").is_none());
    }

    #[test]
    fn cisa_to_cyclonedx_mapping_table() {
        assert_eq!(
            cisa_to_cyclonedx_justification(
                VexJustification::VulnerableCodeNotPresent
            ),
            "code_not_present"
        );
        assert_eq!(
            cisa_to_cyclonedx_justification(
                VexJustification::VulnerableCodeNotInExecutePath
            ),
            "code_not_reachable"
        );
        assert_eq!(
            cisa_to_cyclonedx_justification(
                VexJustification::VulnerableCodeCannotBeControlledByAdversary
            ),
            "protected_at_perimeter"
        );
        assert_eq!(
            cisa_to_cyclonedx_justification(
                VexJustification::InlineMitigationsAlreadyExist
            ),
            "protected_by_mitigating_control"
        );
        assert_eq!(
            cisa_to_cyclonedx_justification(
                VexJustification::ComponentNotPresent
            ),
            "requires_dependency"
        );
    }

    #[test]
    fn fp_mark_with_justification_is_not_affected() {
        let suppressed = vec![finding(cve("CVE-1", None))];
        let mut fp = HashMap::new();
        fp.insert(
            "CVE-1".into(),
            FpEntry {
                comment: "unused".into(),
                timestamp_secs: 1,
                user: None,
                host: None,
                project_id: None,
                justification: Some("vulnerable_code_not_present".into()),
                status: Some("not_affected".into()),
                detail: Some("never imported".into()),
            },
        );
        let stmts = derive_vex_statements(
            &[],
            &suppressed,
            &fp,
            &VexConfig::default(),
        );
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(
            stmts[0].justification,
            Some(VexJustification::VulnerableCodeNotPresent)
        );
        assert_eq!(stmts[0].detail.as_deref(), Some("never imported"));
    }

    #[test]
    fn fp_mark_without_justification_uses_fallback() {
        let suppressed = vec![finding(cve("CVE-2", None))];
        let mut fp = HashMap::new();
        fp.insert(
            "CVE-2".into(),
            FpEntry {
                comment: "triaged".into(),
                timestamp_secs: 1,
                user: None,
                host: None,
                project_id: None,
                justification: None,
                status: None,
                detail: None,
            },
        );
        let stmts = derive_vex_statements(
            &[],
            &suppressed,
            &fp,
            &VexConfig::default(),
        );
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(
            stmts[0].justification,
            Some(VexJustification::InlineMitigationsAlreadyExist)
        );
        assert_eq!(stmts[0].detail.as_deref(), Some("triaged"));
    }

    #[test]
    fn reachable_false_defaults_to_in_triage() {
        let findings = vec![finding(cve("CVE-3", Some(false)))];
        let stmts = derive_vex_statements(
            &findings,
            &[],
            &HashMap::new(),
            &VexConfig::default(),
        );
        assert_eq!(stmts[0].status, VexStatus::UnderInvestigation);
        assert!(stmts[0].justification.is_none());
        assert_eq!(stmts[0].status.as_cyclonedx_state(), "in_triage");
    }

    #[test]
    fn reachable_false_opt_in_not_affected() {
        let findings = vec![finding(cve("CVE-4", Some(false)))];
        let cfg = VexConfig {
            reachability_not_affected: true,
            ..VexConfig::default()
        };
        let stmts =
            derive_vex_statements(&findings, &[], &HashMap::new(), &cfg);
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(
            stmts[0].justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );
    }

    #[test]
    fn reachable_true_is_affected() {
        let findings = vec![finding(cve("CVE-5", Some(true)))];
        let stmts = derive_vex_statements(
            &findings,
            &[],
            &HashMap::new(),
            &VexConfig::default(),
        );
        assert_eq!(stmts[0].status, VexStatus::Affected);
        assert_eq!(stmts[0].status.as_cyclonedx_state(), "exploitable");
    }

    #[test]
    fn reachable_unknown_is_in_triage() {
        let findings = vec![finding(cve("CVE-6", None))];
        let stmts = derive_vex_statements(
            &findings,
            &[],
            &HashMap::new(),
            &VexConfig::default(),
        );
        assert_eq!(stmts[0].status, VexStatus::UnderInvestigation);
    }

    #[test]
    fn fp_mark_takes_precedence_over_reachable_true() {
        let suppressed = vec![finding(cve("CVE-FP", Some(true)))];
        let mut fp = HashMap::new();
        fp.insert(
            "CVE-FP".into(),
            FpEntry {
                comment: "accepted".into(),
                timestamp_secs: 1,
                user: None,
                host: None,
                project_id: None,
                justification: Some(
                    "vulnerable_code_not_in_execute_path".into(),
                ),
                status: Some("not_affected".into()),
                detail: None,
            },
        );
        // Suppressed path (FP) must win; active findings list is empty after filter.
        let stmts = derive_vex_statements(
            &[],
            &suppressed,
            &fp,
            &VexConfig::default(),
        );
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(
            stmts[0].justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );
    }

    #[test]
    fn upgrade_plan_fixed_version_does_not_infer_fixed_status() {
        let mut f = finding(cve("CVE-FIXED-PLAN", Some(true)));
        f.upgrade_plan.minimal_fixed_version = "2.0.0".into();
        let stmts = derive_vex_statements(
            &[f],
            &[],
            &HashMap::new(),
            &VexConfig::default(),
        );
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].status, VexStatus::Affected);
        assert_ne!(stmts[0].status.as_str(), "fixed");
    }

    #[test]
    fn blank_product_id_normalizes_to_none() {
        let mut cfg = VexConfig {
            product_id: Some("  ".into()),
            author_namespace: Some("".into()),
            author_name: "  ".into(),
            ..VexConfig::default()
        };
        cfg.normalize_optional_ids();
        assert!(cfg.product_id.is_none());
        assert!(cfg.author_namespace.is_none());
        assert_eq!(cfg.author_name, DEFAULT_VEX_AUTHOR_NAME);
        assert!(cfg.effective_product_id(Some("")).is_none());
        assert_eq!(
            cfg.effective_product_id(Some(" pkg:app@1 ")),
            Some("pkg:app@1")
        );
    }

    #[test]
    fn cyclonedx_analysis_includes_justification_when_not_affected() {
        let stmt = VexStatement {
            cve_id: "CVE-7".into(),
            purl: "pkg:pypi/demo@1.0.0".into(),
            status: VexStatus::NotAffected,
            justification: Some(
                VexJustification::VulnerableCodeNotInExecutePath,
            ),
            detail: Some("detail".into()),
        };
        let analysis = cyclonedx_analysis_for(&stmt);
        assert_eq!(analysis["state"], "not_affected");
        assert_eq!(analysis["justification"], "code_not_reachable");
        assert_eq!(analysis["detail"], "detail");
    }
}
