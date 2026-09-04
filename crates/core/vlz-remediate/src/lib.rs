// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

//! FR-040 upgrade-plan planning on findings.
//!
//! This crate owns upgrade-plan data types and the planner implementation.

use semver::Version;
use vlz_db::{
    AffectedRangeType, CveRecord, DeclarationKind, Package,
    PackageDeclarationLocation,
};

pub const MIN_FIXED_VERSION_UNKNOWN: &str = "unknown";

mod remediator;
pub use remediator::{
    CargoRemediator, NpmRemediator, RemediationContext, RemediationError,
    Remediator, remediation_apply_strategy_for_finding,
};

/// Upgrade plan confidence for a planned remediation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UpgradePlanConfidence {
    High,
    Unknown,
}

impl UpgradePlanConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Unknown => "unknown",
        }
    }
}

/// Planned apply strategy (Phase 1 is plan-only).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStrategy {
    Unavailable,
    Npm,
    Cargo,
}

impl ApplyStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Npm => "npm",
            Self::Cargo => "cargo",
        }
    }
}

/// Where the vulnerable dependency is declared.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Direct,
    Transitive,
    Unknown,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Transitive => "transitive",
            Self::Unknown => "unknown",
        }
    }
}

/// Finding-level upgrade plan.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct UpgradePlan {
    /// Minimal fixed version that satisfies the fixed events across all CVEs.
    /// `unknown` means Phase 1 could not compute it without a registry.
    pub minimal_fixed_version: String,
    pub dependency_kind: DependencyKind,
    pub apply_strategy: ApplyStrategy,
    pub confidence: UpgradePlanConfidence,
}

/// Compute a Phase-1 upgrade plan for a single finding.
///
/// Algorithm:
/// - Consider only ECOSYSTEM/SEMVER affected ranges and their `fixed` events.
/// - Parse fixed versions as SemVer; if any fixed version is unparsable => `unknown`.
/// - For multiple fixed versions: compute the max (intersection of >= constraints).
/// - Dependency kind: `direct` if any declaration is a manifest; `transitive` if
///   only lockfile declarations exist; otherwise `unknown`.
pub fn plan_upgrade_for_finding(
    _package: &Package,
    declarations: &[PackageDeclarationLocation],
    cves: &[CveRecord],
) -> UpgradePlan {
    let dependency_kind = match (
        declarations
            .iter()
            .any(|d| d.kind == DeclarationKind::Manifest),
        declarations
            .iter()
            .any(|d| d.kind == DeclarationKind::Lockfile),
    ) {
        (true, _) => DependencyKind::Direct,
        (false, true) => DependencyKind::Transitive,
        _ => DependencyKind::Unknown,
    };

    let (min_fixed_known, min_fixed_version) =
        compute_minimal_fixed_version(cves);

    let confidence =
        if min_fixed_known && dependency_kind != DependencyKind::Unknown {
            UpgradePlanConfidence::High
        } else {
            UpgradePlanConfidence::Unknown
        };

    let mut plan = UpgradePlan {
        minimal_fixed_version: min_fixed_version,
        dependency_kind,
        apply_strategy: ApplyStrategy::Unavailable,
        confidence,
    };
    plan.apply_strategy = remediation_apply_strategy_for_finding(
        _package,
        &plan.minimal_fixed_version,
        declarations,
    );
    plan
}

fn compute_minimal_fixed_version(cves: &[CveRecord]) -> (bool, String) {
    let mut max_fixed: Option<Version> = None;
    let mut saw_fixed = false;
    for cve in cves {
        for range in &cve.affected_ranges {
            match range.range_type {
                AffectedRangeType::Ecosystem | AffectedRangeType::Semver => {}
                AffectedRangeType::Git => continue,
            }
            for ev in &range.events {
                if let Some(fixed) = ev.fixed.as_deref() {
                    saw_fixed = true;
                    let parsed = parse_fixed_version(fixed);
                    let Some(parsed) = parsed else {
                        return (false, MIN_FIXED_VERSION_UNKNOWN.to_string());
                    };
                    max_fixed = Some(match max_fixed {
                        Some(existing) => existing.max(parsed),
                        None => parsed,
                    });
                }
            }
        }
    }
    if !saw_fixed {
        return (false, MIN_FIXED_VERSION_UNKNOWN.to_string());
    }
    // Every `saw_fixed` path either returns early on parse failure or updates
    // `max_fixed`, so this is always `Some` here.
    (
        true,
        max_fixed
            .expect("saw_fixed implies a parsed max_fixed version")
            .to_string(),
    )
}

fn parse_fixed_version(s: &str) -> Option<Version> {
    let trimmed = s.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    Version::parse(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::{AffectedEvent, AffectedRange, CvssVersion};

    fn empty_decl(kind: DeclarationKind) -> PackageDeclarationLocation {
        PackageDeclarationLocation {
            path: "Cargo.toml".to_string(),
            start_line: 1,
            end_line: None,
            kind,
        }
    }

    fn cve_with_fixed(
        id: &str,
        range_type: AffectedRangeType,
        fixed: Option<&str>,
    ) -> CveRecord {
        let mut events = vec![];
        if let Some(fixed) = fixed {
            events.push(AffectedEvent {
                fixed: Some(fixed.to_string()),
                ..Default::default()
            });
        }
        let affected_ranges = if events.is_empty() {
            vec![]
        } else {
            vec![AffectedRange {
                range_type,
                events,
                package_name: None,
                ecosystem: None,
            }]
        };
        CveRecord {
            id: id.to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "desc".to_string(),
            reachable: None,
            advisory_symbols: vec![],
            evidence: vec![],
            symbol_usage: None,
            affected_ranges,
        }
    }

    #[test]
    fn plan_unknown_when_no_fixed_events() {
        let pkg = Package {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves =
            vec![cve_with_fixed("CVE-1", AffectedRangeType::Ecosystem, None)];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, MIN_FIXED_VERSION_UNKNOWN);
        assert_eq!(plan.dependency_kind, DependencyKind::Direct);
        assert_eq!(plan.confidence, UpgradePlanConfidence::Unknown);
        assert_eq!(plan.apply_strategy, ApplyStrategy::Unavailable);
    }

    #[test]
    fn plan_uses_max_fixed_version_ecosystem() {
        let pkg = Package {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves = vec![
            cve_with_fixed(
                "CVE-1",
                AffectedRangeType::Ecosystem,
                Some("1.0.0"),
            ),
            cve_with_fixed(
                "CVE-2",
                AffectedRangeType::Ecosystem,
                Some("2.0.0"),
            ),
        ];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, "2.0.0");
        assert_eq!(plan.confidence, UpgradePlanConfidence::High);
    }

    #[test]
    fn plan_uses_semver_fixed_versions() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("pypi".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves = vec![
            cve_with_fixed("CVE-1", AffectedRangeType::Semver, Some("1.2.3")),
            cve_with_fixed("CVE-2", AffectedRangeType::Semver, Some("1.2.4")),
        ];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, "1.2.4");
        assert_eq!(plan.confidence, UpgradePlanConfidence::High);
    }

    #[test]
    fn plan_returns_unknown_on_unparsable_fixed() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves = vec![cve_with_fixed(
            "CVE-1",
            AffectedRangeType::Ecosystem,
            Some("not-a-version"),
        )];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, MIN_FIXED_VERSION_UNKNOWN);
        assert_eq!(plan.confidence, UpgradePlanConfidence::Unknown);
    }

    #[test]
    fn plan_ignores_git_ranges_for_fixed() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Lockfile)];
        let cves = vec![cve_with_fixed(
            "CVE-1",
            AffectedRangeType::Git,
            Some("deadbeef"),
        )];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.dependency_kind, DependencyKind::Transitive);
        assert_eq!(plan.minimal_fixed_version, MIN_FIXED_VERSION_UNKNOWN);
        assert_eq!(plan.confidence, UpgradePlanConfidence::Unknown);
    }

    #[test]
    fn plan_unknown_dependency_kind_without_declarations() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let cves = vec![cve_with_fixed(
            "CVE-1",
            AffectedRangeType::Ecosystem,
            Some("1.2.3"),
        )];
        let plan = plan_upgrade_for_finding(&pkg, &[], &cves);
        assert_eq!(plan.dependency_kind, DependencyKind::Unknown);
        assert_eq!(plan.minimal_fixed_version, "1.2.3");
        assert_eq!(plan.confidence, UpgradePlanConfidence::Unknown);
    }

    #[test]
    fn plan_accepts_v_prefixed_semver() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves = vec![cve_with_fixed(
            "CVE-1",
            AffectedRangeType::Semver,
            Some("v2.0.0"),
        )];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, "2.0.0");
        assert_eq!(plan.confidence, UpgradePlanConfidence::High);
    }

    #[test]
    fn enum_as_str_covers_all_variants() {
        assert_eq!(UpgradePlanConfidence::High.as_str(), "high");
        assert_eq!(UpgradePlanConfidence::Unknown.as_str(), "unknown");
        assert_eq!(ApplyStrategy::Unavailable.as_str(), "unavailable");
        assert_eq!(ApplyStrategy::Npm.as_str(), "npm");
        assert_eq!(ApplyStrategy::Cargo.as_str(), "cargo");
        assert_eq!(DependencyKind::Direct.as_str(), "direct");
        assert_eq!(DependencyKind::Transitive.as_str(), "transitive");
        assert_eq!(DependencyKind::Unknown.as_str(), "unknown");
    }
}
