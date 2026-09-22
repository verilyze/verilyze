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
    BUN_BIN_NAME, BUN_IGNORE_SCRIPTS_FLAG, BUN_LOCK_FILE_NAME,
    BUNDLE_BIN_NAME, BUNDLE_SKIP_INSTALL_FLAG, BunRemediator, CARGO_BIN_NAME,
    CARGO_LOCK_FILE_NAME, CARGO_MANIFEST_FILE_NAME, CargoRemediator,
    GO_BIN_NAME, GO_MANIFEST_FILE_NAME, GO_SUM_FILE_NAME, GRADLE_BIN_NAME,
    GRADLE_BUILDSCRIPT_LOCK_FILE_NAME, GRADLE_LOCK_FILE_NAME,
    GRADLE_MANIFEST_BUILD_FILE_NAME, GRADLE_MANIFEST_BUILD_KTS_FILE_NAME,
    GRADLE_SETTINGS_FILE_NAME, GRADLE_SETTINGS_KTS_FILE_NAME,
    GRADLE_VERSION_CATALOG_FILE_NAME, GoRemediator, GradleRemediator,
    MAVEN_MANIFEST_FILE_NAME, MavenRemediator, NPM_BIN_NAME,
    NPM_IGNORE_SCRIPTS_FLAG, NPM_LOCKFILE_NPM_SHRINKWRAP_JSON,
    NPM_LOCKFILE_PACKAGE_LOCK_JSON, NPM_MANIFEST_FILE_NAME, NPM_NO_SAVE_FLAG,
    NPM_PACKAGE_LOCK_ONLY_FLAG, NpmRemediator, PNPM_BIN_NAME,
    PNPM_LOCK_FILE_NAME, PNPM_LOCKFILE_ONLY_FLAG, POETRY_BIN_NAME,
    POETRY_LOCK_FILE_NAME, POETRY_LOCK_FLAG, PYLOCK_TOML_FILE_NAME,
    PYTHON_MANIFEST_FILE_NAME, PnpmRemediator, PythonRemediator,
    RUBY_LOCK_GEMFILE_LOCK_FILE_NAME, RUBY_LOCK_GEMS_LOCKED_FILE_NAME,
    RUBY_MANIFEST_GEMFILE_FILE_NAME, RUBY_MANIFEST_GEMS_RB_FILE_NAME,
    RemediationContext, RemediationError, RemediationPreview, Remediator,
    RubyGemsRemediator, UV_BIN_NAME, UV_LOCK_FILE_NAME, UV_NO_SYNC_FLAG,
    YARN_BERRY_SKIP_BUILD_FLAG, YARN_BERRY_UP_SUBCOMMAND, YARN_BIN_NAME,
    YARN_CLASSIC_IGNORE_SCRIPTS_FLAG, YARN_CLASSIC_LOCKFILE_MARKER,
    YARN_CLASSIC_UPGRADE_SUBCOMMAND, YARN_LOCK_FILE_NAME, YarnLockFlavor,
    YarnRemediator, bun_update_argv, bundle_add_argv, cargo_update_argv,
    detect_yarn_lock_flavor, go_get_argv, gradle_update_argv,
    npm_install_argv, pnpm_update_argv, poetry_add_argv,
    remediation_apply_strategy_for_finding, uv_add_argv, yarn_remediate_argv,
    yarn_up_argv,
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

/// Planned apply strategy for a finding-level upgrade plan.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStrategy {
    Unavailable,
    Npm,
    Cargo,
    Python,
    Yarn,
    Pnpm,
    Bun,
    Go,
    RubyGems,
    Gradle,
    Maven,
}

impl ApplyStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Python => "python",
            Self::Yarn => "yarn",
            Self::Pnpm => "pnpm",
            Self::Bun => "bun",
            Self::Go => "go",
            // Serde snake_case for `RubyGems` is `ruby_gems`; keep in sync.
            Self::RubyGems => "ruby_gems",
            Self::Gradle => "gradle",
            Self::Maven => "maven",
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

/// Compute a finding-level upgrade plan (FR-040 planner; pure, no I/O).
///
/// Algorithm:
/// - Consider only ECOSYSTEM/SEMVER affected ranges (ignore GIT).
/// - For each range, walk events in order. An interval is
///   `[introduced, fixed)` (introduced defaults to `0` when a fixed or
///   last_affected appears first). Collect `fixed` endpoints for intervals
///   that contain the installed package version.
/// - Across CVEs, take the maximum of those covering fixed versions (one
///   upgrade must clear every advisory).
/// - A covering `last_affected` without `fixed`, an unparsable fixed, or an
///   unparsable installed version yields `unknown`.
/// - Dependency kind: `direct` if any declaration is a manifest; `transitive`
///   if only lockfile declarations exist; otherwise `unknown`.
pub fn plan_upgrade_for_finding(
    package: &Package,
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
        fixed_version_for_installed(&package.version, cves);

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
        package,
        &plan.minimal_fixed_version,
        declarations,
    );
    plan
}

/// Minimal fixed version for intervals that contain `installed` (FR-040).
///
/// Returns `(true, version)` when a covering fix exists; `(false, "unknown")`
/// when the installed pin is unparsable, a covering interval has no fix, or
/// no covering fixed interval was found.
fn fixed_version_for_installed(
    installed: &str,
    cves: &[CveRecord],
) -> (bool, String) {
    let Some(installed_ver) = parse_fixed_version(installed) else {
        return (false, MIN_FIXED_VERSION_UNKNOWN.to_string());
    };

    let mut max_fixed: Option<Version> = None;
    for cve in cves {
        for range in &cve.affected_ranges {
            match range.range_type {
                AffectedRangeType::Ecosystem | AffectedRangeType::Semver => {}
                AffectedRangeType::Git => continue,
            }
            match covering_fixed_from_range(&installed_ver, &range.events) {
                Ok(None) => {}
                Ok(Some(fixed)) => {
                    max_fixed = Some(match max_fixed {
                        Some(existing) => existing.max(fixed),
                        None => fixed,
                    });
                }
                Err(()) => {
                    return (false, MIN_FIXED_VERSION_UNKNOWN.to_string());
                }
            }
        }
    }
    match max_fixed {
        Some(v) => (true, v.to_string()),
        None => (false, MIN_FIXED_VERSION_UNKNOWN.to_string()),
    }
}

/// Walk OSV events for one range. `Ok(Some(fixed))` when the installed
/// version sits in a `[introduced, fixed)` interval. `Ok(None)` when no
/// covering interval applies. `Err(())` for unparsable fixed/introduced or a
/// covering `last_affected` with no fix.
fn covering_fixed_from_range(
    installed: &Version,
    events: &[vlz_db::AffectedEvent],
) -> Result<Option<Version>, ()> {
    let zero = Version::new(0, 0, 0);
    let mut lower: Option<Version> = None;
    let mut covering_fixed: Option<Version> = None;

    for ev in events {
        if let Some(introduced) = ev.introduced.as_deref() {
            let intro = if introduced.trim() == "0" {
                zero.clone()
            } else {
                parse_fixed_version(introduced).ok_or(())?
            };
            lower = Some(intro);
        }
        if let Some(fixed_s) = ev.fixed.as_deref() {
            let fixed = parse_fixed_version(fixed_s).ok_or(())?;
            let intro = lower.clone().unwrap_or_else(|| zero.clone());
            if *installed >= intro && *installed < fixed {
                covering_fixed = Some(match covering_fixed {
                    Some(existing) => existing.max(fixed.clone()),
                    None => fixed.clone(),
                });
            }
            // Next interval (if any) starts at this fixed endpoint until a
            // later `introduced` resets the lower bound.
            lower = Some(fixed);
        } else if let Some(last_s) = ev.last_affected.as_deref() {
            let last = parse_fixed_version(last_s).ok_or(())?;
            let intro = lower.clone().unwrap_or_else(|| zero.clone());
            // Inclusive upper bound for last_affected intervals.
            if *installed >= intro && *installed <= last {
                return Err(());
            }
            lower = Some(last);
        }
    }
    Ok(covering_fixed)
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
            in_kev: None,
            epss: None,
            epss_percentile: None,
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
        // Installed pin must sit inside each CVE's [introduced, fixed)
        // interval (default introduced 0) so both candidates apply.
        let pkg = Package {
            name: "requests".to_string(),
            version: "0.5.0".to_string(),
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

    fn cve_with_events(
        id: &str,
        range_type: AffectedRangeType,
        events: Vec<AffectedEvent>,
    ) -> CveRecord {
        CveRecord {
            id: id.to_string(),
            cvss_score: Some(7.0),
            cvss_version: Some(CvssVersion::V3),
            description: "desc".to_string(),
            reachable: None,
            advisory_symbols: vec![],
            evidence: vec![],
            symbol_usage: None,
            affected_ranges: vec![AffectedRange {
                range_type,
                events,
                package_name: None,
                ecosystem: None,
            }],
            in_kev: None,
            epss: None,
            epss_percentile: None,
        }
    }

    /// RUSTSEC-2026-0097 shape: three patched lines in one SEMVER range.
    fn rand_multi_interval_cve() -> CveRecord {
        cve_with_events(
            "RUSTSEC-2026-0097",
            AffectedRangeType::Semver,
            vec![
                AffectedEvent {
                    introduced: Some("0.7.0".to_string()),
                    ..Default::default()
                },
                AffectedEvent {
                    fixed: Some("0.8.6".to_string()),
                    ..Default::default()
                },
                AffectedEvent {
                    introduced: Some("0.9.0".to_string()),
                    ..Default::default()
                },
                AffectedEvent {
                    fixed: Some("0.9.3".to_string()),
                    ..Default::default()
                },
                AffectedEvent {
                    introduced: Some("0.10.0".to_string()),
                    ..Default::default()
                },
                AffectedEvent {
                    fixed: Some("0.10.1".to_string()),
                    ..Default::default()
                },
            ],
        )
    }

    #[test]
    fn plan_picks_covering_interval_for_rand_shaped_advisory() {
        let decls = vec![PackageDeclarationLocation {
            path: "Cargo.lock".to_string(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        }];
        let cves = vec![rand_multi_interval_cve()];

        let on_09 = Package {
            name: "rand".to_string(),
            version: "0.9.2".to_string(),
            ecosystem: Some(vlz_db::CRATES_IO_ECOSYSTEM.to_string()),
        };
        let plan = plan_upgrade_for_finding(&on_09, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, "0.9.3");
        assert_eq!(plan.apply_strategy, ApplyStrategy::Cargo);
        assert_eq!(plan.confidence, UpgradePlanConfidence::High);

        let on_08 = Package {
            name: "rand".to_string(),
            version: "0.8.5".to_string(),
            ecosystem: Some(vlz_db::CRATES_IO_ECOSYSTEM.to_string()),
        };
        assert_eq!(
            plan_upgrade_for_finding(&on_08, &decls, &cves)
                .minimal_fixed_version,
            "0.8.6"
        );

        let on_10 = Package {
            name: "rand".to_string(),
            version: "0.10.0".to_string(),
            ecosystem: Some(vlz_db::CRATES_IO_ECOSYSTEM.to_string()),
        };
        assert_eq!(
            plan_upgrade_for_finding(&on_10, &decls, &cves)
                .minimal_fixed_version,
            "0.10.1"
        );
    }

    #[test]
    fn plan_multi_interval_npm_package_same_shape() {
        let pkg = Package {
            name: "left-pad".to_string(),
            version: "0.9.2".to_string(),
            ecosystem: Some(vlz_db::NPM_ECOSYSTEM.to_string()),
        };
        let decls = vec![PackageDeclarationLocation {
            path: "package-lock.json".to_string(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        }];
        let cves = vec![rand_multi_interval_cve()];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, "0.9.3");
        assert_eq!(plan.apply_strategy, ApplyStrategy::Npm);
    }

    #[test]
    fn plan_unknown_when_covering_last_affected_has_no_fixed() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves = vec![cve_with_events(
            "CVE-1",
            AffectedRangeType::Ecosystem,
            vec![
                AffectedEvent {
                    introduced: Some("0".to_string()),
                    ..Default::default()
                },
                AffectedEvent {
                    last_affected: Some("1.2.3".to_string()),
                    ..Default::default()
                },
            ],
        )];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, MIN_FIXED_VERSION_UNKNOWN);
        assert_eq!(plan.confidence, UpgradePlanConfidence::Unknown);
    }

    #[test]
    fn plan_unknown_when_installed_version_unparsable() {
        let pkg = Package {
            name: "foo".to_string(),
            version: "any".to_string(),
            ecosystem: Some("npm".to_string()),
        };
        let decls = vec![empty_decl(DeclarationKind::Manifest)];
        let cves = vec![cve_with_fixed(
            "CVE-1",
            AffectedRangeType::Ecosystem,
            Some("1.2.3"),
        )];
        let plan = plan_upgrade_for_finding(&pkg, &decls, &cves);
        assert_eq!(plan.minimal_fixed_version, MIN_FIXED_VERSION_UNKNOWN);
        assert_eq!(plan.confidence, UpgradePlanConfidence::Unknown);
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
        assert_eq!(ApplyStrategy::Python.as_str(), "python");
        assert_eq!(ApplyStrategy::Yarn.as_str(), "yarn");
        assert_eq!(ApplyStrategy::Pnpm.as_str(), "pnpm");
        assert_eq!(ApplyStrategy::Bun.as_str(), "bun");
        assert_eq!(ApplyStrategy::Go.as_str(), "go");
        assert_eq!(ApplyStrategy::RubyGems.as_str(), "ruby_gems");
        assert_eq!(ApplyStrategy::Gradle.as_str(), "gradle");
        assert_eq!(ApplyStrategy::Maven.as_str(), "maven");
        assert_eq!(DependencyKind::Direct.as_str(), "direct");
        assert_eq!(DependencyKind::Transitive.as_str(), "transitive");
        assert_eq!(DependencyKind::Unknown.as_str(), "unknown");
    }

    #[test]
    fn plan_sets_npm_and_cargo_apply_strategy_from_lockfiles() {
        use vlz_db::{CRATES_IO_ECOSYSTEM, NPM_ECOSYSTEM};

        let npm_pkg = Package {
            name: "left-pad".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some(NPM_ECOSYSTEM.to_string()),
        };
        let npm_decls = vec![PackageDeclarationLocation {
            path: "package-lock.json".to_string(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        }];
        let npm_plan = plan_upgrade_for_finding(
            &npm_pkg,
            &npm_decls,
            &[cve_with_fixed(
                "CVE-1",
                AffectedRangeType::Ecosystem,
                Some("2.0.0"),
            )],
        );
        assert_eq!(npm_plan.apply_strategy, ApplyStrategy::Npm);
        assert_eq!(npm_plan.dependency_kind, DependencyKind::Transitive);
        assert_eq!(npm_plan.confidence, UpgradePlanConfidence::High);

        let cargo_pkg = Package {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
        };
        let cargo_decls = vec![PackageDeclarationLocation {
            path: "Cargo.lock".to_string(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        }];
        let cargo_plan = plan_upgrade_for_finding(
            &cargo_pkg,
            &cargo_decls,
            &[cve_with_fixed(
                "CVE-2",
                AffectedRangeType::Semver,
                Some("1.0.200"),
            )],
        );
        assert_eq!(cargo_plan.apply_strategy, ApplyStrategy::Cargo);
        assert_eq!(cargo_plan.minimal_fixed_version, "1.0.200");
    }
}
