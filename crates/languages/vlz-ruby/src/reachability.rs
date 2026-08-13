// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::PathBuf;
use vlz_db::RUBYGEMS_ECOSYSTEM;
use vlz_reachability_trait::{
    LineCommentStyle, ReachabilityAnalyzer, TierBContext, TierBDecision,
    TierCDecision, TierCResult, line_code_for_symbol_match,
    list_files_with_ext, note_tier_b_file_read_attempt,
    push_reachability_evidence, qualified_symbol_in_code,
    reachability_evidence_at_cap,
};

#[derive(Debug, Default)]
pub struct RubyTierBAnalyzer;

impl RubyTierBAnalyzer {
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

fn ruby_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scoped_roots(context) {
        if let Ok(mut found) =
            list_files_with_ext(&root, context.exclude_dir_names, "rb")
        {
            files.append(&mut found);
        }
    }
    files.sort();
    files.dedup();
    files
}

fn require_regex() -> regex::Regex {
    regex::Regex::new(
        r#"(?:\brequire(?:_relative)?\s*(?:\(\s*)?|\bautoload\s+[^,]+,\s*)['"]([^'"]+)['"]"#,
    )
    .expect("valid Ruby require regex")
}

fn normalized(value: &str) -> String {
    value.replace('-', "_").to_ascii_lowercase()
}

fn compact_name(value: &str) -> String {
    normalized(value).replace('_', "")
}

fn required_features(content: &str) -> HashSet<String> {
    require_regex()
        .captures_iter(content)
        .filter_map(|captures| captures.get(1))
        .map(|value| {
            value
                .as_str()
                .trim_start_matches("./")
                .split('/')
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn package_is_required(package: &str, features: &HashSet<String>) -> bool {
    let package_norm = normalized(package);
    let package_compact = compact_name(package);
    features.iter().any(|feature| {
        let feature_norm = normalized(feature);
        feature_norm == package_norm
            || compact_name(feature) == package_compact
    })
}

impl ReachabilityAnalyzer for RubyTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "ruby"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &[RUBYGEMS_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let mut features = HashSet::new();
        for path in ruby_files(context) {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    note_tier_b_file_read_attempt(true);
                    features.extend(required_features(&content));
                }
                Err(_) => note_tier_b_file_read_attempt(false),
            }
        }
        if package_is_required(&context.package.name, &features) {
            TierBDecision::Reachable
        } else if context.package.name.len() < 2 {
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
        let mut evidence = Vec::new();
        let mut saw = false;
        for path in ruby_files(context) {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                // Keep quoted require paths for feature matching; strip quotes
                // only for advisory symbol matching (same pattern as JS).
                let features = required_features(trimmed);
                let code = line_code_for_symbol_match(
                    trimmed,
                    LineCommentStyle::Hash,
                );
                for symbol in advisory_symbols {
                    if qualified_symbol_in_code(&code, symbol)
                        || package_is_required(symbol, &features)
                    {
                        saw = true;
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
        let decision = if saw {
            TierCDecision::Reachable
        } else if context.package.name.len() < 2 {
            TierCDecision::Unknown
        } else {
            TierCDecision::NotReachable
        };
        TierCResult { decision, evidence }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use vlz_db::Package;

    #[test]
    fn extracts_require_relative_and_autoload() {
        let features = required_features(
            "require 'rack/test'\nrequire_relative './my_gem/x'\n\
             autoload :JSON, \"json\"\n",
        );
        assert!(features.contains("rack"));
        assert!(features.contains("my_gem"));
        assert!(features.contains("json"));
    }

    #[test]
    fn tier_b_matches_hyphen_to_underscore() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.rb"), "require 'my_gem'\n")
            .unwrap();
        let package = Package {
            name: "my-gem".into(),
            version: "1.0.0".into(),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "ruby",
            manifest_paths: &[],
        };
        assert_eq!(
            RubyTierBAnalyzer::new().analyze_tier_b(&context),
            TierBDecision::Reachable
        );
    }

    #[test]
    fn tier_b_matches_compact_activesupport_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.rb"),
            "require 'active_support'\n",
        )
        .unwrap();
        let package = Package {
            name: "activesupport".into(),
            version: "7.0.0".into(),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "ruby",
            manifest_paths: &[],
        };
        assert_eq!(
            RubyTierBAnalyzer::new().analyze_tier_b(&context),
            TierBDecision::Reachable
        );
    }

    #[test]
    fn tier_b_unknown_for_short_name_and_not_reachable_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.rb"), "require 'rack'\n").unwrap();
        let excludes = HashSet::new();
        let short = Package {
            name: "a".into(),
            version: "1".into(),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.into()),
        };
        let ctx_short = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &short,
            language: "ruby",
            manifest_paths: &[],
        };
        assert_eq!(
            RubyTierBAnalyzer::new().analyze_tier_b(&ctx_short),
            TierBDecision::Unknown
        );
        let other = Package {
            name: "unrelated".into(),
            version: "1".into(),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.into()),
        };
        let ctx_other = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &other,
            language: "ruby",
            manifest_paths: &[],
        };
        assert_eq!(
            RubyTierBAnalyzer::new().analyze_tier_b(&ctx_other),
            TierBDecision::NotReachable
        );
    }

    #[test]
    fn tier_c_finds_symbol_evidence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.rb"),
            "require 'rack'\nRack::Builder.new\n",
        )
        .unwrap();
        let package = Package {
            name: "rack".into(),
            version: "2.2.8".into(),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "ruby",
            manifest_paths: &[],
        };
        let analyzer = RubyTierBAnalyzer::new();
        assert!(analyzer.supports_tier_c());
        assert_eq!(analyzer.language_name(), "ruby");
        assert_eq!(analyzer.ecosystems(), &[RUBYGEMS_ECOSYSTEM]);
        let result = analyzer.analyze_tier_c(&context, &["rack".into()]);
        assert_eq!(result.decision, TierCDecision::Reachable);
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn scoped_roots_use_manifest_parents() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("app");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("main.rb"), "require 'rack'\n").unwrap();
        let package = Package {
            name: "rack".into(),
            version: "1".into(),
            ecosystem: Some(RUBYGEMS_ECOSYSTEM.into()),
        };
        let excludes = HashSet::new();
        let manifest = nested.join("Gemfile");
        std::fs::write(&manifest, "").unwrap();
        let manifests = [manifest];
        let context = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: &excludes,
            package: &package,
            language: "ruby",
            manifest_paths: &manifests,
        };
        assert_eq!(
            RubyTierBAnalyzer::new().analyze_tier_b(&context),
            TierBDecision::Reachable
        );
    }
}
