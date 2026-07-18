// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tier B reachability orchestration for language analyzers (FR-032).

#![deny(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use vlz_cve_client::{
    AdvisorySymbols, advisory_fingerprint, extract_advisory_symbols,
};
use vlz_db::{CveRecord, Package};
pub use vlz_reachability_trait::{
    MAX_REACHABILITY_EVIDENCE_PER_CVE, ReachabilityAnalyzer,
    ReachabilityEvidence, SYMBOL_USAGE_NOT_FOUND, SYMBOL_USAGE_UNKNOWN,
    SYMBOL_USAGE_USED, TierBContext, TierBDecision, TierCDecision,
    TierCResult, measure_tier_b_counters, note_tier_b_file_read_attempt,
    reset_tier_b_counters, sanitize_advisory_symbols,
    snapshot_tier_b_counters,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedDecision {
    decision: TierBDecisionDisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum TierBDecisionDisk {
    Reachable,
    NotReachable,
    Unknown,
}

impl From<TierBDecision> for TierBDecisionDisk {
    fn from(value: TierBDecision) -> Self {
        match value {
            TierBDecision::Reachable => Self::Reachable,
            TierBDecision::NotReachable => Self::NotReachable,
            TierBDecision::Unknown => Self::Unknown,
        }
    }
}

impl From<TierBDecisionDisk> for TierBDecision {
    fn from(value: TierBDecisionDisk) -> Self {
        match value {
            TierBDecisionDisk::Reachable => Self::Reachable,
            TierBDecisionDisk::NotReachable => Self::NotReachable,
            TierBDecisionDisk::Unknown => Self::Unknown,
        }
    }
}

fn persistent_cache_enabled() -> bool {
    std::env::var("VLZ_REACHABILITY_PERSIST_CACHE")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn decision_cache_path(scan_root: &std::path::Path) -> PathBuf {
    scan_root.join(".vlz").join("reachability-cache.json")
}

/// Bump when persisted reachability cache key shape changes (Tier C per-CVE keys).
pub const PERSISTED_REACHABILITY_CACHE_VERSION: &str = "2";

/// Persisted Tier B decision key (package-level).
pub fn tier_b_persisted_cache_key(
    package: &Package,
    context: Option<&PackageContext>,
) -> String {
    format!(
        "v{PERSISTED_REACHABILITY_CACHE_VERSION}|tier-b|{}",
        decision_cache_key(package, context)
    )
}

/// Persisted Tier C decision key (per CVE + advisory fingerprint).
pub fn tier_c_persisted_cache_key(
    cve_id: &str,
    package: &Package,
    advisory_fingerprint: &str,
    context: Option<&PackageContext>,
) -> String {
    format!(
        "v{PERSISTED_REACHABILITY_CACHE_VERSION}|tier-c|{cve_id}|{}|{advisory_fingerprint}",
        decision_cache_key(package, context)
    )
}

fn load_decision_cache(
    scan_root: &std::path::Path,
) -> HashMap<String, PersistedDecision> {
    let path = decision_cache_path(scan_root);
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_decision_cache(
    scan_root: &std::path::Path,
    cache: &HashMap<String, PersistedDecision>,
) {
    let path = decision_cache_path(scan_root);
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string(cache) {
        let _ = std::fs::write(path, json);
    }
}

fn decision_cache_key(
    package: &Package,
    context: Option<&PackageContext>,
) -> String {
    let mut parts = vec![
        package.name.clone(),
        package.version.clone(),
        package.ecosystem.clone().unwrap_or_default(),
    ];
    if let Some(ctx) = context {
        let mut langs: Vec<_> = ctx.languages.iter().cloned().collect();
        langs.sort();
        parts.push(langs.join(","));
        let mut manifests = ctx.manifest_paths.clone();
        manifests.sort();
        for path in manifests {
            parts.push(path.display().to_string());
            let stamp = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs().to_string())
                .unwrap_or_else(|| "0".to_string());
            parts.push(stamp);
        }
    }
    parts.join("|")
}

pub fn apply_tier_b_to_findings(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    findings: &mut [(Package, Vec<CveRecord>)],
    package_contexts: &HashMap<Package, PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
) {
    let mut cache: HashMap<Package, TierBDecision> = HashMap::new();
    let persist = persistent_cache_enabled();
    let mut persistent_cache = if persist {
        load_decision_cache(scan_root)
    } else {
        HashMap::new()
    };
    let mut dirty = false;
    for (pkg, recs) in findings.iter_mut() {
        let decision = *cache.entry(pkg.clone()).or_insert_with(|| {
            let key =
                tier_b_persisted_cache_key(pkg, package_contexts.get(pkg));
            if let Some(p) = persistent_cache.get(&key) {
                return p.decision.into();
            }
            choose_tier_b_decision(
                scan_root,
                exclude_dir_names,
                pkg,
                package_contexts.get(pkg),
                analyzers,
            )
        });
        if persist {
            let key =
                tier_b_persisted_cache_key(pkg, package_contexts.get(pkg));
            if let std::collections::hash_map::Entry::Vacant(entry) =
                persistent_cache.entry(key)
            {
                entry.insert(PersistedDecision {
                    decision: decision.into(),
                });
                dirty = true;
            }
        }
        let mapped = decision.as_option_bool();
        for rec in recs.iter_mut() {
            rec.reachable = mapped;
        }
    }
    if persist && dirty {
        save_decision_cache(scan_root, &persistent_cache);
    }
}

fn choose_tier_c_result(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    package: &Package,
    context: Option<&PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
    advisory_symbols: &[String],
) -> TierCResult {
    let Some(ctx) = context else {
        return TierCResult::unknown();
    };
    if ctx.languages.is_empty() || advisory_symbols.is_empty() {
        return TierCResult::unknown();
    }
    let advisory_symbols = sanitize_advisory_symbols(advisory_symbols);
    if advisory_symbols.is_empty() {
        return TierCResult::unknown();
    }
    let Some(ecosystem) = package.ecosystem.as_deref() else {
        return TierCResult::unknown();
    };

    let mut languages: Vec<String> = ctx.languages.iter().cloned().collect();
    languages.sort();
    let mut results = Vec::new();
    for language in languages {
        let analyzer = analyzers.iter().find(|analyzer| {
            analyzer.language_name() == language.as_str()
                && analyzer.ecosystems().contains(&ecosystem)
                && analyzer.supports_tier_c()
        });
        let Some(analyzer) = analyzer else {
            results.push(TierCResult::unknown());
            continue;
        };
        let context = TierBContext {
            scan_root,
            exclude_dir_names,
            package,
            language: &language,
            manifest_paths: &ctx.manifest_paths,
        };
        results.push(analyzer.analyze_tier_c(&context, &advisory_symbols));
    }
    vlz_reachability_trait::merge_tier_c_results(results)
}

fn choose_tier_d_result(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    package: &Package,
    context: Option<&PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
    advisory_symbols: &[String],
) -> TierCResult {
    let Some(ctx) = context else {
        return TierCResult::unknown();
    };
    if ctx.languages.is_empty() || advisory_symbols.is_empty() {
        return TierCResult::unknown();
    }
    let advisory_symbols = sanitize_advisory_symbols(advisory_symbols);
    if advisory_symbols.is_empty() {
        return TierCResult::unknown();
    }
    let Some(ecosystem) = package.ecosystem.as_deref() else {
        return TierCResult::unknown();
    };

    let mut languages: Vec<String> = ctx.languages.iter().cloned().collect();
    languages.sort();
    let mut results = Vec::new();
    for language in languages {
        let analyzer = analyzers.iter().find(|analyzer| {
            analyzer.language_name() == language.as_str()
                && analyzer.ecosystems().contains(&ecosystem)
                && analyzer.supports_tier_d()
        });
        let Some(analyzer) = analyzer else {
            results.push(TierCResult::unknown());
            continue;
        };
        let context = TierBContext {
            scan_root,
            exclude_dir_names,
            package,
            language: &language,
            manifest_paths: &ctx.manifest_paths,
        };
        results.push(analyzer.analyze_tier_d(&context, &advisory_symbols));
    }
    vlz_reachability_trait::merge_tier_c_results(results)
}

fn evidence_to_db_locations(
    evidence: &[ReachabilityEvidence],
    scan_root: &std::path::Path,
) -> Vec<vlz_db::CveEvidenceLocation> {
    evidence
        .iter()
        .map(|e| {
            let path = e
                .path
                .strip_prefix(scan_root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| e.path.to_string_lossy().into_owned());
            vlz_db::CveEvidenceLocation {
                path,
                start_line: e.start_line,
                end_line: e.end_line,
                symbol: e.symbol.clone(),
            }
        })
        .collect()
}

fn apply_symbol_metadata(
    rec: &mut CveRecord,
    advisory_symbols: &[String],
    result: &TierCResult,
    scan_root: &std::path::Path,
) {
    rec.advisory_symbols = advisory_symbols.to_vec();
    rec.evidence = evidence_to_db_locations(&result.evidence, scan_root);
    rec.symbol_usage = Some(if !rec.evidence.is_empty() {
        SYMBOL_USAGE_USED.to_string()
    } else {
        match result.decision {
            TierCDecision::NotReachable => SYMBOL_USAGE_NOT_FOUND.to_string(),
            TierCDecision::Reachable | TierCDecision::Unknown => {
                SYMBOL_USAGE_UNKNOWN.to_string()
            }
        }
    });
}

fn vuln_for_cve_id<'a>(
    raw_vulns: &'a [serde_json::Value],
    cve_id: &str,
) -> Option<&'a serde_json::Value> {
    raw_vulns.iter().find(|v| {
        v.get("id")
            .and_then(|id| id.as_str())
            .is_some_and(|id| id == cve_id)
    })
}

/// Apply Tier C per-CVE reachability when advisory symbol data is present (FR-032 phase 2a).
/// When a CVE has no symbol metadata, the existing Tier B `reachable` value is preserved.
pub fn apply_tier_c_to_findings(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    findings: &mut [(Package, Vec<CveRecord>)],
    package_contexts: &HashMap<Package, PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
    raw_vulns_by_package: &HashMap<Package, Vec<serde_json::Value>>,
) {
    let persist = persistent_cache_enabled();
    let mut persistent_cache = if persist {
        load_decision_cache(scan_root)
    } else {
        HashMap::new()
    };
    let mut dirty = false;
    for (pkg, recs) in findings.iter_mut() {
        let Some(raw_vulns) = raw_vulns_by_package.get(pkg) else {
            continue;
        };
        let ctx = package_contexts.get(pkg);
        for rec in recs.iter_mut() {
            let tier_b_reachable = rec.reachable;
            let Some(vuln) = vuln_for_cve_id(raw_vulns, &rec.id) else {
                continue;
            };
            let advisory = extract_advisory_symbols(vuln, pkg);
            if !advisory.has_symbol_data {
                continue;
            }
            let fingerprint = advisory_fingerprint(&advisory);
            let symbols = sanitize_advisory_symbols(&advisory.symbols);
            if symbols.is_empty() {
                continue;
            }
            let result = choose_tier_c_result(
                scan_root,
                exclude_dir_names,
                pkg,
                ctx,
                analyzers,
                &symbols,
            );
            if persist {
                let key = tier_c_persisted_cache_key(
                    &rec.id,
                    pkg,
                    &fingerprint,
                    ctx,
                );
                let new_entry = PersistedDecision {
                    decision: result.decision.into(),
                };
                let changed = persistent_cache.get(&key) != Some(&new_entry);
                if changed {
                    persistent_cache.insert(key, new_entry);
                    dirty = true;
                }
            }
            apply_symbol_metadata(rec, &symbols, &result, scan_root);
            match result.decision {
                TierCDecision::Reachable => rec.reachable = Some(true),
                TierCDecision::NotReachable => rec.reachable = Some(false),
                TierCDecision::Unknown => {
                    if tier_b_reachable.is_none() {
                        rec.reachable = None;
                    }
                }
            }
        }
    }
    if persist && dirty {
        save_decision_cache(scan_root, &persistent_cache);
    }
}

/// Refine Tier C unknowns using Tier D analyzers when enabled (optional stretch).
pub fn apply_tier_d_to_findings(
    scan_root: &std::path::Path,
    exclude_dir_names: &HashSet<String>,
    findings: &mut [(Package, Vec<CveRecord>)],
    package_contexts: &HashMap<Package, PackageContext>,
    analyzers: &[Box<dyn ReachabilityAnalyzer>],
    raw_vulns_by_package: &HashMap<Package, Vec<serde_json::Value>>,
) {
    for (pkg, recs) in findings.iter_mut() {
        let Some(raw_vulns) = raw_vulns_by_package.get(pkg) else {
            continue;
        };
        let ctx = package_contexts.get(pkg);
        for rec in recs.iter_mut() {
            if rec.reachable.is_some() {
                continue;
            }
            let Some(vuln) = vuln_for_cve_id(raw_vulns, &rec.id) else {
                continue;
            };
            let AdvisorySymbols {
                symbols,
                has_symbol_data,
            } = extract_advisory_symbols(vuln, pkg);
            if !has_symbol_data {
                continue;
            }
            let symbols = sanitize_advisory_symbols(&symbols);
            if symbols.is_empty() {
                continue;
            }
            let tier_d = choose_tier_d_result(
                scan_root,
                exclude_dir_names,
                pkg,
                ctx,
                analyzers,
                &symbols,
            );
            apply_symbol_metadata(rec, &symbols, &tier_d, scan_root);
            match tier_d.decision {
                TierCDecision::Reachable => rec.reachable = Some(true),
                TierCDecision::NotReachable => rec.reachable = Some(false),
                TierCDecision::Unknown => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[derive(Debug)]
    struct CountingAnalyzer {
        language: &'static str,
        ecosystems: &'static [&'static str],
        decision: TierBDecision,
        calls: Arc<AtomicUsize>,
    }

    impl ReachabilityAnalyzer for CountingAnalyzer {
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
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.decision
        }
    }

    fn pkg(name: &str, ecosystem: Option<&str>) -> Package {
        Package {
            name: name.to_string(),
            version: "1.0".to_string(),
            ecosystem: ecosystem.map(ToOwned::to_owned),
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
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
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
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
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
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
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

    #[test]
    fn choose_tier_b_unknown_when_ecosystem_missing() {
        let decision = choose_tier_b_decision(
            std::path::Path::new("."),
            &HashSet::new(),
            &pkg("serde", None),
            Some(&PackageContext {
                languages: HashSet::from(["rust".to_string()]),
                manifest_paths: vec![],
            }),
            &[],
        );
        assert_eq!(decision, TierBDecision::Unknown);
    }

    #[test]
    fn choose_tier_b_unknown_when_languages_empty() {
        let decision = choose_tier_b_decision(
            std::path::Path::new("."),
            &HashSet::new(),
            &pkg("serde", Some("crates.io")),
            Some(&PackageContext::default()),
            &[],
        );
        assert_eq!(decision, TierBDecision::Unknown);
    }

    #[test]
    fn choose_tier_b_not_reachable_when_all_languages_not_reachable() {
        let package = pkg("serde", Some("crates.io"));
        let decision = choose_tier_b_decision(
            std::path::Path::new("."),
            &HashSet::new(),
            &package,
            Some(&PackageContext {
                languages: HashSet::from(["rust".to_string()]),
                manifest_paths: vec![],
            }),
            &[Box::new(StubAnalyzer {
                language: "rust",
                ecosystems: &["crates.io"],
                decision: TierBDecision::NotReachable,
            })],
        );
        assert_eq!(decision, TierBDecision::NotReachable);
    }

    #[test]
    fn choose_tier_b_reachable_short_circuits() {
        let package = pkg("serde", Some("crates.io"));
        let decision = choose_tier_b_decision(
            std::path::Path::new("."),
            &HashSet::new(),
            &package,
            Some(&PackageContext {
                languages: HashSet::from([
                    "rust".to_string(),
                    "python".to_string(),
                ]),
                manifest_paths: vec![],
            }),
            &[Box::new(StubAnalyzer {
                language: "rust",
                ecosystems: &["crates.io"],
                decision: TierBDecision::Reachable,
            })],
        );
        assert_eq!(decision, TierBDecision::Reachable);
    }

    #[test]
    fn persistent_cache_enabled_recognizes_expected_values() {
        temp_env::with_var(
            "VLZ_REACHABILITY_PERSIST_CACHE",
            Some("true"),
            || {
                assert!(persistent_cache_enabled());
            },
        );
        temp_env::with_var(
            "VLZ_REACHABILITY_PERSIST_CACHE",
            Some("1"),
            || {
                assert!(persistent_cache_enabled());
            },
        );
        temp_env::with_var(
            "VLZ_REACHABILITY_PERSIST_CACHE",
            Some("no"),
            || {
                assert!(!persistent_cache_enabled());
            },
        );
    }

    #[test]
    fn decision_cache_path_appends_vlz_file() {
        let root = std::path::Path::new("/tmp/example");
        let path = decision_cache_path(root);
        assert!(path.ends_with(".vlz/reachability-cache.json"));
    }

    #[test]
    fn decision_cache_key_stable_for_sorted_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest_a = dir.path().join("b.toml");
        let manifest_b = dir.path().join("a.toml");
        std::fs::write(&manifest_a, "a").expect("write");
        std::fs::write(&manifest_b, "b").expect("write");
        let package = pkg("serde", Some("crates.io"));
        let context = PackageContext {
            languages: HashSet::from([
                "python".to_string(),
                "rust".to_string(),
            ]),
            manifest_paths: vec![manifest_a, manifest_b],
        };
        let key = decision_cache_key(&package, Some(&context));
        assert!(key.contains("serde"));
        assert!(key.contains("1.0"));
        assert!(key.contains("crates.io"));
        assert!(key.contains("python,rust") || key.contains("rust,python"));
        assert!(key.contains("a.toml"));
        assert!(key.contains("b.toml"));
    }

    #[test]
    fn load_decision_cache_handles_missing_and_invalid_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let none = load_decision_cache(dir.path());
        assert!(none.is_empty());

        let path = decision_cache_path(dir.path());
        std::fs::create_dir_all(path.parent().expect("parent"))
            .expect("mkdir");
        std::fs::write(&path, "{invalid json").expect("write");
        let invalid = load_decision_cache(dir.path());
        assert!(invalid.is_empty());
    }

    #[test]
    fn save_then_load_decision_cache_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cache = HashMap::new();
        cache.insert(
            "k".to_string(),
            PersistedDecision {
                decision: TierBDecisionDisk::Reachable,
            },
        );
        save_decision_cache(dir.path(), &cache);
        let loaded = load_decision_cache(dir.path());
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            TierBDecision::from(loaded.get("k").expect("entry").decision),
            TierBDecision::Reachable
        );
    }

    #[test]
    fn apply_tier_b_memoizes_per_package_within_run() {
        let package = pkg("serde", Some("crates.io"));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["rust".to_string()]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(CountingAnalyzer {
                language: "rust",
                ecosystems: &["crates.io"],
                decision: TierBDecision::NotReachable,
                calls: calls.clone(),
            })];
        let mut findings = vec![
            (
                package.clone(),
                vec![CveRecord {
                    id: "CVE-1".to_string(),
                    cvss_score: None,
                    cvss_version: None,
                    description: String::new(),
                    reachable: None,
                    advisory_symbols: Vec::new(),
                    evidence: Vec::new(),
                    symbol_usage: None,
                }],
            ),
            (
                package,
                vec![CveRecord {
                    id: "CVE-2".to_string(),
                    cvss_score: None,
                    cvss_version: None,
                    description: String::new(),
                    reachable: None,
                    advisory_symbols: Vec::new(),
                    evidence: Vec::new(),
                    symbol_usage: None,
                }],
            ),
        ];
        apply_tier_b_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(findings[0].1[0].reachable, Some(false));
        assert_eq!(findings[1].1[0].reachable, Some(false));
    }

    struct TierCAnalyzer {
        reachable_symbols: HashSet<String>,
    }

    impl ReachabilityAnalyzer for TierCAnalyzer {
        fn language_name(&self) -> &'static str {
            "python"
        }

        fn ecosystems(&self) -> &'static [&'static str] {
            &["PyPI"]
        }

        fn analyze_tier_b(&self, _: &TierBContext<'_>) -> TierBDecision {
            TierBDecision::Reachable
        }

        fn supports_tier_c(&self) -> bool {
            true
        }

        fn analyze_tier_c(
            &self,
            _: &TierBContext<'_>,
            advisory_symbols: &[String],
        ) -> TierCResult {
            if advisory_symbols
                .iter()
                .any(|s| self.reachable_symbols.contains(s))
            {
                TierCResult::from_decision(TierCDecision::Reachable)
            } else {
                TierCResult::from_decision(TierCDecision::NotReachable)
            }
        }
    }

    #[test]
    fn apply_tier_c_diverges_per_cve_on_same_package() {
        let package = Package {
            name: "http".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("PyPI".to_string()),
        };
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["python".to_string()]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(TierCAnalyzer {
                reachable_symbols: HashSet::from(["safe_fn".to_string()]),
            })];
        let mut findings = vec![(
            package.clone(),
            vec![
                CveRecord {
                    id: "CVE-A".to_string(),
                    cvss_score: None,
                    cvss_version: None,
                    description: String::new(),
                    reachable: Some(true),
                    advisory_symbols: Vec::new(),
                    evidence: Vec::new(),
                    symbol_usage: None,
                },
                CveRecord {
                    id: "CVE-B".to_string(),
                    cvss_score: None,
                    cvss_version: None,
                    description: String::new(),
                    reachable: Some(true),
                    advisory_symbols: Vec::new(),
                    evidence: Vec::new(),
                    symbol_usage: None,
                },
            ],
        )];
        let raw_vulns = HashMap::from([(
            package.clone(),
            vec![
                serde_json::json!({
                    "id": "CVE-A",
                    "affected": [{
                        "package": { "name": "http", "ecosystem": "PyPI" },
                        "ecosystem_specific": { "affected_functions": ["safe_fn"] }
                    }]
                }),
                serde_json::json!({
                    "id": "CVE-B",
                    "affected": [{
                        "package": { "name": "http", "ecosystem": "PyPI" },
                        "ecosystem_specific": { "affected_functions": ["other_fn"] }
                    }]
                }),
            ],
        )]);
        apply_tier_c_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
            &raw_vulns,
        );
        assert_eq!(findings[0].1[0].reachable, Some(true));
        assert_eq!(findings[0].1[1].reachable, Some(false));
    }

    #[test]
    fn tier_c_persisted_cache_key_differs_from_tier_b_for_same_package() {
        let package = pkg("http", Some("PyPI"));
        let context = PackageContext {
            languages: HashSet::from(["python".to_string()]),
            manifest_paths: vec![],
        };
        let tier_b = tier_b_persisted_cache_key(&package, Some(&context));
        let tier_c = tier_c_persisted_cache_key(
            "CVE-2024-1",
            &package,
            "safe_fn|other_fn",
            Some(&context),
        );
        assert_ne!(tier_b, tier_c);
        assert!(tier_b.contains("|tier-b|"));
        assert!(tier_c.contains("|tier-c|"));
        assert!(tier_c.contains("CVE-2024-1"));
    }

    #[test]
    fn apply_tier_c_preserves_tier_b_when_no_symbol_data() {
        let package = pkg("requests", Some("PyPI"));
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["python".to_string()]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(TierCAnalyzer {
                reachable_symbols: HashSet::new(),
            })];
        let mut findings = vec![(
            package.clone(),
            vec![CveRecord {
                id: "CVE-NO-SYM".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: Some(true),
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
            }],
        )];
        let raw_vulns = HashMap::from([(
            package.clone(),
            vec![serde_json::json!({
                "id": "CVE-NO-SYM",
                "affected": [{
                    "package": { "name": "requests", "ecosystem": "PyPI" },
                    "ecosystem_specific": { "severity": "HIGH" }
                }]
            })],
        )]);
        apply_tier_c_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
            &raw_vulns,
        );
        assert_eq!(
            findings[0].1[0].reachable,
            Some(true),
            "Tier B reachable must be kept when advisory has no symbol data"
        );
    }

    struct TierCUnknownAnalyzer;

    impl ReachabilityAnalyzer for TierCUnknownAnalyzer {
        fn language_name(&self) -> &'static str {
            "python"
        }

        fn ecosystems(&self) -> &'static [&'static str] {
            &["PyPI"]
        }

        fn analyze_tier_b(&self, _: &TierBContext<'_>) -> TierBDecision {
            TierBDecision::Reachable
        }

        fn supports_tier_c(&self) -> bool {
            true
        }

        fn analyze_tier_c(
            &self,
            _: &TierBContext<'_>,
            _: &[String],
        ) -> TierCResult {
            TierCResult::from_decision(TierCDecision::Unknown)
        }
    }

    #[test]
    fn apply_tier_c_unknown_preserves_tier_b_when_set() {
        let package = pkg("http", Some("PyPI"));
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["python".to_string()]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(TierCUnknownAnalyzer)];
        let mut findings = vec![(
            package.clone(),
            vec![CveRecord {
                id: "CVE-UNK".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: Some(true),
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
            }],
        )];
        let raw_vulns = HashMap::from([(
            package.clone(),
            vec![serde_json::json!({
                "id": "CVE-UNK",
                "affected": [{
                    "package": { "name": "http", "ecosystem": "PyPI" },
                    "ecosystem_specific": { "modules": ["http.mod"] }
                }]
            })],
        )]);
        apply_tier_c_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
            &raw_vulns,
        );
        assert_eq!(findings[0].1[0].reachable, Some(true));
    }

    struct TierDAnalyzer {
        reachable_symbols: HashSet<String>,
    }

    impl ReachabilityAnalyzer for TierDAnalyzer {
        fn language_name(&self) -> &'static str {
            "python"
        }

        fn ecosystems(&self) -> &'static [&'static str] {
            &["PyPI"]
        }

        fn analyze_tier_b(&self, _: &TierBContext<'_>) -> TierBDecision {
            TierBDecision::Unknown
        }

        fn supports_tier_c(&self) -> bool {
            true
        }

        fn analyze_tier_c(
            &self,
            _: &TierBContext<'_>,
            _: &[String],
        ) -> TierCResult {
            TierCResult::from_decision(TierCDecision::Unknown)
        }

        fn supports_tier_d(&self) -> bool {
            true
        }

        fn analyze_tier_d(
            &self,
            _: &TierBContext<'_>,
            advisory_symbols: &[String],
        ) -> TierCResult {
            if advisory_symbols
                .iter()
                .any(|s| self.reachable_symbols.contains(s))
            {
                TierCResult::from_decision(TierCDecision::Reachable)
            } else {
                TierCResult::from_decision(TierCDecision::NotReachable)
            }
        }
    }

    #[test]
    fn apply_tier_d_refines_unknown_tier_c() {
        let package = pkg("http", Some("PyPI"));
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["python".to_string()]),
                manifest_paths: vec![],
            },
        );
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(TierDAnalyzer {
                reachable_symbols: HashSet::from(["deep_fn".to_string()]),
            })];
        let mut findings = vec![(
            package.clone(),
            vec![CveRecord {
                id: "CVE-D".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: None,
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
            }],
        )];
        let raw_vulns = HashMap::from([(
            package.clone(),
            vec![serde_json::json!({
                "id": "CVE-D",
                "affected": [{
                    "package": { "name": "http", "ecosystem": "PyPI" },
                    "ecosystem_specific": { "affected_functions": ["deep_fn"] }
                }]
            })],
        )]);
        apply_tier_d_to_findings(
            std::path::Path::new("."),
            &HashSet::new(),
            &mut findings,
            &contexts,
            &analyzers,
            &raw_vulns,
        );
        assert_eq!(findings[0].1[0].reachable, Some(true));
    }

    #[test]
    fn apply_tier_b_persists_decisions_when_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let package = pkg("serde", Some("crates.io"));
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["rust".to_string()]),
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
            package.clone(),
            vec![CveRecord {
                id: "CVE-P".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: None,
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
            }],
        )];
        temp_env::with_var(
            "VLZ_REACHABILITY_PERSIST_CACHE",
            Some("yes"),
            || {
                apply_tier_b_to_findings(
                    dir.path(),
                    &HashSet::new(),
                    &mut findings,
                    &contexts,
                    &analyzers,
                );
                let cache = load_decision_cache(dir.path());
                assert!(!cache.is_empty());
                assert_eq!(findings[0].1[0].reachable, Some(false));
            },
        );
    }

    #[test]
    fn apply_tier_c_persists_decisions_when_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let package = pkg("http", Some("PyPI"));
        let mut contexts = HashMap::new();
        contexts.insert(
            package.clone(),
            PackageContext {
                languages: HashSet::from(["python".to_string()]),
                manifest_paths: vec![],
            },
        );
        let calls = Arc::new(AtomicUsize::new(0));
        struct CountingTierCAnalyzer {
            calls: Arc<AtomicUsize>,
        }
        impl ReachabilityAnalyzer for CountingTierCAnalyzer {
            fn language_name(&self) -> &'static str {
                "python"
            }
            fn ecosystems(&self) -> &'static [&'static str] {
                &["PyPI"]
            }
            fn analyze_tier_b(&self, _: &TierBContext<'_>) -> TierBDecision {
                TierBDecision::Reachable
            }
            fn supports_tier_c(&self) -> bool {
                true
            }
            fn analyze_tier_c(
                &self,
                _: &TierBContext<'_>,
                _: &[String],
            ) -> TierCResult {
                self.calls.fetch_add(1, Ordering::Relaxed);
                TierCResult::from_decision(TierCDecision::NotReachable)
            }
        }
        let analyzers: Vec<Box<dyn ReachabilityAnalyzer>> =
            vec![Box::new(CountingTierCAnalyzer {
                calls: calls.clone(),
            })];
        let mut findings = vec![(
            package.clone(),
            vec![CveRecord {
                id: "CVE-C".to_string(),
                cvss_score: None,
                cvss_version: None,
                description: String::new(),
                reachable: None,
                advisory_symbols: Vec::new(),
                evidence: Vec::new(),
                symbol_usage: None,
            }],
        )];
        let raw_vulns = HashMap::from([(
            package.clone(),
            vec![serde_json::json!({
                "id": "CVE-C",
                "affected": [{
                    "package": { "name": "http", "ecosystem": "PyPI" },
                    "ecosystem_specific": { "modules": ["pkg.sub"] }
                }]
            })],
        )]);
        temp_env::with_var(
            "VLZ_REACHABILITY_PERSIST_CACHE",
            Some("yes"),
            || {
                apply_tier_c_to_findings(
                    dir.path(),
                    &HashSet::new(),
                    &mut findings,
                    &contexts,
                    &analyzers,
                    &raw_vulns,
                );
                assert_eq!(calls.load(Ordering::Relaxed), 1);
                assert_eq!(findings[0].1[0].reachable, Some(false));
                apply_tier_c_to_findings(
                    dir.path(),
                    &HashSet::new(),
                    &mut findings,
                    &contexts,
                    &analyzers,
                    &raw_vulns,
                );
                assert_eq!(
                    calls.load(Ordering::Relaxed),
                    2,
                    "second run should re-run analyzers for fresh evidence"
                );
                let cache = load_decision_cache(dir.path());
                assert!(
                    cache.keys().any(|k| k.contains("|tier-c|")),
                    "cache should contain Tier C key"
                );
            },
        );
    }

    #[test]
    fn tier_b_decision_disk_roundtrip_all_variants() {
        for decision in [
            TierBDecision::Reachable,
            TierBDecision::NotReachable,
            TierBDecision::Unknown,
        ] {
            let disk: TierBDecisionDisk = decision.into();
            let back: TierBDecision = disk.into();
            assert_eq!(back, decision);
        }
    }
}
