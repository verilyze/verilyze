// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tier B reachability orchestration for language analyzers (FR-032).

#![deny(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use vlz_db::{CveRecord, Package};
pub use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision,
    note_tier_b_file_read_attempt, reset_tier_b_counters,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDecision {
    decision: TierBDecisionDisk,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    scan_root
        .join(".vlz")
        .join("reachability-tier-b-cache.json")
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
            let key = decision_cache_key(pkg, package_contexts.get(pkg));
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
            let key = decision_cache_key(pkg, package_contexts.get(pkg));
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
        assert!(path.ends_with(".vlz/reachability-tier-b-cache.json"));
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
}
