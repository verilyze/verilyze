// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tier B reachability orchestration for language analyzers (FR-032).

#![deny(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use vlz_db::{CveRecord, Package};
pub use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision,
};

#[derive(Debug, Clone, Default)]
pub struct PackageContext {
    pub languages: HashSet<String>,
    pub manifest_paths: Vec<PathBuf>,
}

fn choose_tier_b_decision(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    package: &Package,
    context: Option<&PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
) -> TierBDecision {
    let Some(ctx) = context else {
        return TierBDecision::Unknown;
    };
    if ctx.languages.is_empty() {
        return TierBDecision::Unknown;
    }
    let Some(ecosystem) = package.ecosystem.as_deref() else {
        return TierBDecision::Unknown;
    };

    let mut saw_unknown = false;
    let mut saw_not_reachable = false;
    for language in &ctx.languages {
        let analyzer = analyzers.iter().find(|analyzer| {
            analyzer.language_name() == language.as_str()
                && analyzer.ecosystems().contains(&ecosystem)
        });
        let Some(analyzer) = analyzer else {
            saw_unknown = true;
            continue;
        };
        let context = TierBContext {
            scan_root,
            exclude_dir_names,
            package,
            language,
            manifest_paths: &ctx.manifest_paths,
        };
        match analyzer.analyze_tier_b(&context) {
            TierBDecision::Reachable => return TierBDecision::Reachable,
            TierBDecision::NotReachable => saw_not_reachable = true,
            TierBDecision::Unknown => saw_unknown = true,
        }
    }
    if saw_unknown {
        TierBDecision::Unknown
    } else if saw_not_reachable {
        TierBDecision::NotReachable
    } else {
        TierBDecision::Unknown
    }
}

pub fn apply_tier_b_to_findings(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    findings: &mut [(Package, Vec<CveRecord>)],
    package_contexts: &HashMap<Package, PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
) {
    let mut cache: HashMap<Package, TierBDecision> = HashMap::new();
    for (pkg, recs) in findings.iter_mut() {
        let decision = *cache.entry(pkg.clone()).or_insert_with(|| {
            choose_tier_b_decision(
                scan_root,
                exclude_dir_names,
                pkg,
                package_contexts.get(pkg),
                analyzers,
            )
        });
        let mapped = decision.as_option_bool();
        for rec in recs.iter_mut() {
            rec.reachable = mapped;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[derive(Debug)]
    struct StubAnalyzer {
        language: &'static str,
        ecosystems: &'static [&'static str],
        decision: TierBDecision,
    }

    impl ReachabilityAnalyzer for StubAnalyzer {
        fn language_name(&self) -> &'static str {
            self.language
        }
        fn ecosystems(&self) -> &'static [&'static str] {
            self.ecosystems
        }
        fn analyze_tier_b(
            &self,
            _context: &TierBContext<'_>,
        ) -> TierBDecision {
            self.decision
        }
    }

    #[test]
    fn apply_tier_b_unknown_without_context() {
        let pkg = Package {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("crates.io".to_string()),
        };
        let mut findings = vec![(
            pkg.clone(),
            vec![CveRecord {
                id: "CVE-1".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: Some(true),
            }],
        )];
        apply_tier_b_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &HashMap::new(),
            &[],
        );
        assert_eq!(findings[0].1[0].reachable, None);
    }

    #[test]
    fn apply_tier_b_reachable_when_language_analyzer_matches() {
        let pkg = Package {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("crates.io".to_string()),
        };
        let mut contexts = HashMap::new();
        contexts.insert(
            pkg.clone(),
            PackageContext {
                languages: HashSet::from(["rust".to_string()]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(StubAnalyzer {
                language: "rust",
                ecosystems: &["crates.io"],
                decision: TierBDecision::Reachable,
            })];
        let mut findings = vec![(
            pkg,
            vec![CveRecord {
                id: "CVE-1".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: None,
            }],
        )];
        apply_tier_b_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
        );
        assert_eq!(findings[0].1[0].reachable, Some(true));
    }

    #[test]
    fn apply_tier_b_unknown_when_any_language_is_unknown() {
        let pkg = Package {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("crates.io".to_string()),
        };
        let mut contexts = HashMap::new();
        contexts.insert(
            pkg.clone(),
            PackageContext {
                languages: HashSet::from([
                    "rust".to_string(),
                    "python".to_string(),
                ]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(StubAnalyzer {
                language: "rust",
                ecosystems: &["crates.io"],
                decision: TierBDecision::NotReachable,
            })];
        let mut findings = vec![(
            pkg,
            vec![CveRecord {
                id: "CVE-1".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: Some(false),
            }],
        )];
        apply_tier_b_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
        );
        assert_eq!(findings[0].1[0].reachable, None);
    }
}
