// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::PathBuf;
use vlz_db::PUB_ECOSYSTEM;
use vlz_reachability_trait::{
    LineCommentStyle, ReachabilityAnalyzer, TierBContext, TierBDecision,
    TierCResult, line_code_for_symbol_match, list_files_with_ext,
    note_tier_b_file_read_attempt, push_reachability_evidence,
    qualified_symbol_in_code, reachability_evidence_at_cap,
    scrub_c_style_comments, tier_c_decision,
};

/// Tier B/C/D reachability for Dart (`package:` import scan).
#[derive(Debug, Default)]
pub struct DartTierBAnalyzer;

impl DartTierBAnalyzer {
    /// Create a new Dart analyzer.
    pub fn new() -> Self {
        Self
    }
}

fn scoped_roots(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut roots: Vec<_> = context
        .manifest_paths
        .iter()
        .filter_map(|path| path.parent().map(PathBuf::from))
        .collect();
    roots.sort();
    roots.dedup();
    if roots.is_empty() {
        vec![context.scan_root.to_path_buf()]
    } else {
        roots
    }
}

fn dart_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scoped_roots(context) {
        if let Ok(mut found) =
            list_files_with_ext(&root, context.exclude_dir_names, "dart")
        {
            files.append(&mut found);
        }
    }
    files.sort();
    files.dedup();
    files
}

fn directive_regex() -> regex::Regex {
    regex::Regex::new(
        r#"^\s*(?:import|export|part)\s+['"]package:([a-z_][a-z0-9_]*)/"#,
    )
    .expect("valid Dart directive regex")
}

fn imported_packages(content: &str) -> HashSet<String> {
    let re = directive_regex();
    scrub_c_style_comments(content)
        .lines()
        .filter_map(|line| re.captures(line).map(|caps| caps[1].to_string()))
        .collect()
}

impl ReachabilityAnalyzer for DartTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "dart"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &[PUB_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let files = dart_files(context);
        if files.is_empty() {
            return TierBDecision::Unknown;
        }
        let mut imported = HashSet::new();
        for path in files {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    note_tier_b_file_read_attempt(true);
                    imported.extend(imported_packages(&content));
                }
                Err(_) => note_tier_b_file_read_attempt(false),
            }
        }
        if imported.contains(&context.package.name) {
            TierBDecision::Reachable
        } else {
            TierBDecision::NotReachable
        }
    }

    fn supports_tier_c(&self) -> bool {
        true
    }

    fn analyze_tier_c(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCResult {
        let files = dart_files(context);
        let mut evidence = Vec::new();
        for path in &files {
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                let code = line_code_for_symbol_match(
                    line.trim(),
                    LineCommentStyle::SlashSlash,
                );
                for symbol in advisory_symbols {
                    if qualified_symbol_in_code(&code, symbol) {
                        push_reachability_evidence(
                            &mut evidence,
                            path.clone(),
                            (index + 1) as u32,
                            symbol,
                        );
                    }
                }
                if reachability_evidence_at_cap(&evidence) {
                    break;
                }
            }
        }
        let decision = tier_c_decision(
            !evidence.is_empty(),
            !files.is_empty(),
            false,
            false,
        );
        TierCResult { decision, evidence }
    }

    fn supports_tier_d(&self) -> bool {
        cfg!(feature = "tier-d")
    }

    fn analyze_tier_d(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCResult {
        #[cfg(not(feature = "tier-d"))]
        {
            let _ = (context, advisory_symbols);
            TierCResult::unknown()
        }
        #[cfg(feature = "tier-d")]
        {
            use crate::tier_d::{
                collect_dart_import_bindings, selector_match_lines,
                trailing_dart_ident,
            };
            use vlz_reachability_trait::{
                MAX_TIER_D_SOURCE_FILE_BYTES, TierCDecision,
                read_source_if_within_byte_limit,
            };
            let files = dart_files(context);
            if files.is_empty() || advisory_symbols.is_empty() {
                return TierCResult::unknown();
            }
            let mut evidence = Vec::new();
            'files: for path in files {
                let Some(content) = read_source_if_within_byte_limit(
                    &path,
                    MAX_TIER_D_SOURCE_FILE_BYTES,
                ) else {
                    continue;
                };
                let bindings: Vec<_> = collect_dart_import_bindings(&content)
                    .into_iter()
                    .filter(|b| b.package == context.package.name)
                    .collect();
                for binding in &bindings {
                    for sym in advisory_symbols {
                        let Some(ident) = trailing_dart_ident(sym) else {
                            continue;
                        };
                        for line in
                            selector_match_lines(&content, binding, ident)
                        {
                            push_reachability_evidence(
                                &mut evidence,
                                path.clone(),
                                line,
                                sym,
                            );
                            if reachability_evidence_at_cap(&evidence) {
                                break 'files;
                            }
                        }
                    }
                }
            }
            let decision = if evidence.is_empty() {
                TierCDecision::Unknown
            } else {
                TierCDecision::Reachable
            };
            TierCResult { decision, evidence }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use vlz_db::Package;
    use vlz_reachability_trait::TierCDecision;

    fn pkg(name: &str) -> Package {
        Package {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Some(PUB_ECOSYSTEM.into()),
            ..Default::default()
        }
    }

    fn ctx<'a>(
        root: &'a std::path::Path,
        excludes: &'a HashSet<String>,
        package: &'a Package,
        manifests: &'a [std::path::PathBuf],
    ) -> TierBContext<'a> {
        TierBContext {
            scan_root: root,
            exclude_dir_names: excludes,
            package,
            language: "dart",
            manifest_paths: manifests,
        }
    }

    #[test]
    fn identity() {
        let a = DartTierBAnalyzer::new();
        assert_eq!(a.language_name(), "dart");
        assert_eq!(a.ecosystems(), &[PUB_ECOSYSTEM]);
        assert!(a.supports_tier_c());
        assert_eq!(a.supports_tier_d(), cfg!(feature = "tier-d"));
    }

    #[test]
    fn tier_b_reachable_not_reachable_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let ex = HashSet::new();
        let http = pkg("http");
        let a = DartTierBAnalyzer::new();
        assert_eq!(
            a.analyze_tier_b(&ctx(dir.path(), &ex, &http, &[])),
            TierBDecision::Unknown
        );
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        std::fs::write(
            dir.path().join("lib/main.dart"),
            "import 'package:http/http.dart' as http;\n\
             export \"package:meta/meta.dart\";\n\
             part 'package:p/p.dart';\n\
             // import 'package:ghost/ghost.dart';\n",
        )
        .unwrap();
        for name in ["http", "meta", "p"] {
            let p = pkg(name);
            assert_eq!(
                a.analyze_tier_b(&ctx(dir.path(), &ex, &p, &[])),
                TierBDecision::Reachable,
                "{name}"
            );
        }
        for name in ["ghost", "htt"] {
            let p = pkg(name);
            assert_eq!(
                a.analyze_tier_b(&ctx(dir.path(), &ex, &p, &[])),
                TierBDecision::NotReachable,
                "{name}"
            );
        }
    }

    #[test]
    fn tier_b_scopes_to_manifest_parent_and_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir_all(app.join(".dart_tool")).unwrap();
        std::fs::write(
            app.join("main.dart"),
            "import 'package:http/http.dart';\n",
        )
        .unwrap();
        std::fs::write(
            app.join(".dart_tool/gen.dart"),
            "import 'package:gen/gen.dart';\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("other.dart"),
            "import 'package:outside/o.dart';\n",
        )
        .unwrap();
        let manifest = app.join("pubspec.yaml");
        std::fs::write(&manifest, "name: app\n").unwrap();
        let manifests = [manifest];
        let ex: HashSet<String> = [".dart_tool".to_string()].into();
        let a = DartTierBAnalyzer::new();
        let http = pkg("http");
        assert_eq!(
            a.analyze_tier_b(&ctx(dir.path(), &ex, &http, &manifests)),
            TierBDecision::Reachable
        );
        for name in ["gen", "outside"] {
            let p = pkg(name);
            assert_eq!(
                a.analyze_tier_b(&ctx(dir.path(), &ex, &p, &manifests)),
                TierBDecision::NotReachable,
                "{name}"
            );
        }
    }

    #[test]
    fn tier_c_symbol_evidence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.dart"),
            "import 'package:http/http.dart' as http;\n\
             void f() { http.get(u); }\n",
        )
        .unwrap();
        let ex = HashSet::new();
        let p = pkg("http");
        let a = DartTierBAnalyzer::new();
        let hit = a.analyze_tier_c(
            &ctx(dir.path(), &ex, &p, &[]),
            &["http.get".into()],
        );
        assert_eq!(hit.decision, TierCDecision::Reachable);
        assert_eq!(hit.evidence.len(), 1);
        let miss = a.analyze_tier_c(
            &ctx(dir.path(), &ex, &p, &[]),
            &["http.post".into()],
        );
        assert_ne!(miss.decision, TierCDecision::Reachable);
        assert!(miss.evidence.is_empty());
    }

    #[cfg(feature = "tier-d")]
    #[test]
    fn tier_d_alias_selector_and_negative() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.dart"),
            "import 'package:http/http.dart' as h;\n\
             void f() { h.get(u); }\n",
        )
        .unwrap();
        let ex = HashSet::new();
        let p = pkg("http");
        let a = DartTierBAnalyzer::new();
        assert!(a.supports_tier_d());
        let hit = a.analyze_tier_d(
            &ctx(dir.path(), &ex, &p, &[]),
            &["Client.get".into()],
        );
        assert_eq!(hit.decision, TierCDecision::Reachable);
        assert!(!hit.evidence.is_empty());
        let miss = a.analyze_tier_d(
            &ctx(dir.path(), &ex, &p, &[]),
            &["Client.post".into()],
        );
        assert_eq!(miss.decision, TierCDecision::Unknown);
        let none = a.analyze_tier_d(&ctx(dir.path(), &ex, &p, &[]), &[]);
        assert_eq!(none.decision, TierCDecision::Unknown);
        let other = pkg("zzz");
        let wrong = a.analyze_tier_d(
            &ctx(dir.path(), &ex, &other, &[]),
            &["Client.get".into()],
        );
        assert_eq!(wrong.decision, TierCDecision::Unknown);
    }
}
