// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::PathBuf;
use vlz_db::NUGET_ECOSYSTEM;
use vlz_reachability_trait::{
    LineCommentStyle, ReachabilityAnalyzer, TierBContext, TierBDecision,
    TierCResult, line_code_for_symbol_match, list_files_with_ext,
    note_tier_b_file_read_attempt, push_reachability_evidence,
    qualified_symbol_in_code, reachability_evidence_at_cap, tier_c_decision,
};

/// Tier B/C reachability for .NET (`using` / import heuristics on `.cs` /
/// `.fs`).
#[derive(Debug, Default)]
pub struct DotnetTierBAnalyzer;

impl DotnetTierBAnalyzer {
    /// Create a new .NET Tier B analyzer.
    pub fn new() -> Self {
        Self
    }
}

fn scoped_roots(context: &TierBContext<'_>) -> Vec<PathBuf> {
    if context.manifest_paths.is_empty() {
        return vec![context.scan_root.to_path_buf()];
    }
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

fn source_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scoped_roots(context) {
        for ext in ["cs", "fs"] {
            if let Ok(mut found) =
                list_files_with_ext(&root, context.exclude_dir_names, ext)
            {
                files.append(&mut found);
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn using_import_regex() -> regex::Regex {
    regex::Regex::new(
        r#"(?x)
        (?:
          \busing\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*;
          |
          \bopen\s+([A-Za-z_][A-Za-z0-9_.]*)
        )"#,
    )
    .expect("valid .NET using/open regex")
}

fn collected_refs(content: &str) -> HashSet<String> {
    using_import_regex()
        .captures_iter(content)
        .flat_map(|captures| {
            captures
                .iter()
                .skip(1)
                .flatten()
                .map(|m| m.as_str().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn package_tokens(package: &str) -> (String, String) {
    let lower = package.to_ascii_lowercase();
    let compact = lower.replace(['.', '-', '_'], "");
    (lower, compact)
}

fn ref_matches_package(package: &str, refs: &HashSet<String>) -> bool {
    let (pkg_lower, pkg_compact) = package_tokens(package);
    if pkg_lower.len() < 3 {
        return refs.iter().any(|reference| {
            reference.to_ascii_lowercase().contains(&pkg_lower)
        });
    }
    // Prefer namespace-style matches (dots) against NuGet ids.
    let ns_guess = pkg_lower.clone();
    refs.iter().any(|reference| {
        let ref_lower = reference.to_ascii_lowercase();
        let ref_compact = ref_lower.replace(['.', '-', '_'], "");
        ref_lower.contains(&ns_guess)
            || ref_lower.starts_with(&pkg_lower)
            || ref_compact.contains(&pkg_compact)
    })
}

impl ReachabilityAnalyzer for DotnetTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "dotnet"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &[NUGET_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let mut refs = HashSet::new();
        for path in source_files(context) {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    note_tier_b_file_read_attempt(true);
                    refs.extend(collected_refs(&content));
                }
                Err(_) => note_tier_b_file_read_attempt(false),
            }
        }
        if ref_matches_package(&context.package.name, &refs) {
            TierBDecision::Reachable
        } else if context.package.name.len() <= 3 {
            TierBDecision::Unknown
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
        let files = source_files(context);
        let mut evidence = Vec::new();
        for path in &files {
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                let refs = collected_refs(trimmed);
                let code = line_code_for_symbol_match(
                    trimmed,
                    LineCommentStyle::SlashSlash,
                );
                for symbol in advisory_symbols {
                    if qualified_symbol_in_code(&code, symbol)
                        || ref_matches_package(symbol, &refs)
                    {
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
            context.package.name.len() <= 3,
        );
        TierCResult { decision, evidence }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use vlz_db::Package;
    use vlz_reachability_trait::TierCDecision;

    #[test]
    fn extracts_using_and_open() {
        let refs =
            collected_refs("using Newtonsoft.Json;\nopen System.Text\n");
        assert!(refs.iter().any(|r| r.contains("Newtonsoft")));
        assert!(refs.iter().any(|r| r.contains("System.Text")));
    }

    #[test]
    fn tier_b_matches_using_namespace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Program.cs"),
            "using Newtonsoft.Json;\n",
        )
        .unwrap();
        let package = Package {
            name: "Newtonsoft.Json".into(),
            version: "13.0.3".into(),
            ecosystem: Some(NUGET_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "dotnet",
            manifest_paths: &[],
        };
        assert_eq!(
            DotnetTierBAnalyzer::new().analyze_tier_b(&context),
            TierBDecision::Reachable
        );
    }

    #[test]
    fn tier_b_unknown_for_short_name_and_not_reachable_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Program.cs"), "using Foo.Bar;\n")
            .unwrap();
        let excludes = HashSet::new();
        let short = Package {
            name: "Ab".into(),
            version: "1".into(),
            ecosystem: Some(NUGET_ECOSYSTEM.into()),
        };
        let ctx_short = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &short,
            language: "dotnet",
            manifest_paths: &[],
        };
        assert_eq!(
            DotnetTierBAnalyzer::new().analyze_tier_b(&ctx_short),
            TierBDecision::Unknown
        );
        let other = Package {
            name: "Unrelated.Package".into(),
            version: "1".into(),
            ecosystem: Some(NUGET_ECOSYSTEM.into()),
        };
        let ctx_other = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &other,
            language: "dotnet",
            manifest_paths: &[],
        };
        assert_eq!(
            DotnetTierBAnalyzer::new().analyze_tier_b(&ctx_other),
            TierBDecision::NotReachable
        );
    }

    #[test]
    fn tier_c_finds_symbol_evidence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Program.cs"),
            "using Newtonsoft.Json;\nJsonConvert.SerializeObject(x);\n",
        )
        .unwrap();
        let package = Package {
            name: "Newtonsoft.Json".into(),
            version: "13.0.3".into(),
            ecosystem: Some(NUGET_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "dotnet",
            manifest_paths: &[],
        };
        let analyzer = DotnetTierBAnalyzer::new();
        assert!(analyzer.supports_tier_c());
        assert_eq!(analyzer.language_name(), "dotnet");
        assert_eq!(analyzer.ecosystems(), &[NUGET_ECOSYSTEM]);
        let result = analyzer
            .analyze_tier_c(&context, &["JsonConvert.SerializeObject".into()]);
        assert_eq!(result.decision, TierCDecision::Reachable);
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn scoped_roots_use_manifest_parents() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("app");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("Program.cs"), "using Newtonsoft.Json;\n")
            .unwrap();
        let package = Package {
            name: "Newtonsoft.Json".into(),
            version: "13.0.3".into(),
            ecosystem: Some(NUGET_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let manifest = nested.join("App.csproj");
        std::fs::write(&manifest, "<Project />").unwrap();
        let manifests = [manifest];
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "dotnet",
            manifest_paths: &manifests,
        };
        assert_eq!(
            DotnetTierBAnalyzer::new().analyze_tier_b(&context),
            TierBDecision::Reachable
        );
    }
}
