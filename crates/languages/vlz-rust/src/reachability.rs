// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision, list_files_with_ext,
};

#[derive(Debug, Default)]
pub struct RustTierBAnalyzer;

impl RustTierBAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn skip_first_segment(seg: &str) -> bool {
    matches!(seg, "crate" | "self" | "super" | "$crate")
}

fn crate_roots_from_use_path(part: &str) -> Vec<String> {
    let mut out = Vec::new();
    let p = part.trim();
    if p.is_empty() {
        return out;
    }
    let p = p.trim_start_matches("::");
    let first = p
        .split("::")
        .next()
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("");
    if first.is_empty() || skip_first_segment(first) {
        return out;
    }
    let first = first.split(" as ").next().unwrap_or(first).trim();
    if !first.is_empty() && !skip_first_segment(first) {
        out.push(normalize_crate_name(first));
    }
    out
}

fn crate_roots_from_line(line: &str) -> Vec<String> {
    let t = line.trim_start();
    let mut out = Vec::new();

    if let Some(rest) = t.strip_prefix("use ") {
        let rest = rest.trim_start();
        if let Some(inner) = rest
            .strip_prefix('{')
            .and_then(|r| r.split_once('}'))
            .map(|(a, _)| a)
        {
            for part in inner.split(',') {
                out.extend(crate_roots_from_use_path(part.trim()));
            }
            return out;
        }
        if rest.starts_with('{') {
            return out;
        }
        let rest = rest.trim_start_matches("::");
        for part in rest.split(',') {
            out.extend(crate_roots_from_use_path(part.trim()));
        }
        return out;
    }

    if let Some(rest) = t.strip_prefix("extern crate ") {
        let name = rest
            .split(';')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split(" as ")
            .next()
            .unwrap_or("")
            .trim();
        if !name.is_empty() {
            out.push(normalize_crate_name(name));
        }
    }

    out
}

fn collect_rust_import_roots(context: &TierBContext<'_>) -> HashSet<String> {
    let mut roots = HashSet::new();
    let files = match list_files_with_ext(
        context.scan_root,
        context.exclude_dir_names,
        "rs",
    ) {
        Ok(files) => files,
        Err(_) => return roots,
    };
    for path in files {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            for r in crate_roots_from_line(line) {
                roots.insert(r);
            }
        }
    }
    roots
}

fn rust_name_allows_confident_absence(name: &str) -> bool {
    let n = normalize_crate_name(name);
    !n.is_empty()
        && n.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        && n.chars().filter(|c| *c == '_').count() <= 8
}

impl ReachabilityAnalyzer for RustTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "rust"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &["crates.io"]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let rs_files = match list_files_with_ext(
            context.scan_root,
            context.exclude_dir_names,
            "rs",
        ) {
            Ok(files) => files,
            Err(_) => return TierBDecision::Unknown,
        };
        if rs_files.is_empty() {
            return TierBDecision::Unknown;
        }
        let roots = collect_rust_import_roots(context);
        if roots.is_empty() {
            return TierBDecision::Unknown;
        }
        let target = normalize_crate_name(&context.package.name);
        if roots.contains(&target) {
            return TierBDecision::Reachable;
        }
        if rust_name_allows_confident_absence(&context.package.name) {
            TierBDecision::NotReachable
        } else {
            TierBDecision::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn context_for<'a>(
        root: &'a std::path::Path,
        package_name: &str,
    ) -> TierBContext<'a> {
        let package = vlz_db::Package {
            name: package_name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("crates.io".to_string()),
        };
        let exclude = Box::leak(Box::new(HashSet::new()));
        TierBContext {
            scan_root: root,
            exclude_dir_names: exclude,
            package: Box::leak(Box::new(package)),
            language: "rust",
            manifest_paths: Box::leak(Box::new(Vec::<PathBuf>::new())),
        }
    }

    #[test]
    fn helper_normalize_crate_name() {
        assert_eq!(normalize_crate_name("my-crate"), "my_crate");
    }

    #[test]
    fn helper_skip_first_segment_variants() {
        assert!(skip_first_segment("crate"));
        assert!(skip_first_segment("self"));
        assert!(!skip_first_segment("serde"));
    }

    #[test]
    fn helper_crate_roots_from_use_path_variants() {
        assert_eq!(crate_roots_from_use_path("::serde::de"), vec!["serde"]);
        assert_eq!(
            crate_roots_from_use_path("crate::x"),
            Vec::<String>::new()
        );
        assert_eq!(crate_roots_from_use_path(""), Vec::<String>::new());
    }

    #[test]
    fn helper_crate_roots_from_line_variants() {
        assert_eq!(
            crate_roots_from_line("use serde::de::DeserializeOwned;"),
            vec!["serde"]
        );
        assert_eq!(
            crate_roots_from_line(
                "use { serde::de::DeserializeOwned, tokio::sync };"
            ),
            vec!["serde", "tokio"]
        );
        assert!(
            crate_roots_from_line("use { serde::de::DeserializeOwned")
                .is_empty()
        );
        assert_eq!(
            crate_roots_from_line("extern crate my-crate as mine;"),
            vec!["my_crate"]
        );
        assert_eq!(crate_roots_from_line("extern crate libc;"), vec!["libc"]);
        assert!(crate_roots_from_line("use crate::x::y;").is_empty());
        assert!(crate_roots_from_line("fn main() {}").is_empty());
    }

    #[test]
    fn helper_confident_absence_rules() {
        assert!(rust_name_allows_confident_absence("serde_json"));
        assert!(!rust_name_allows_confident_absence("Serde"));
    }

    #[test]
    fn analyze_tier_b_unknown_when_no_rust_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "serde");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_tier_b_reachable_when_use_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "use serde::Deserialize;\n",
        )
        .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "serde");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
    }

    #[test]
    fn analyze_tier_b_not_reachable_when_unambiguous_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(
            dir.path().join("src/main.rs"),
            "use tokio::runtime::Runtime;\n",
        )
        .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "serde");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }

    #[test]
    fn analyze_tier_b_unknown_when_ambiguous_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(
            dir.path().join("src/main.rs"),
            "use tokio::runtime::Runtime;\n",
        )
        .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "Serde");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_tier_b_unknown_when_only_internal_paths_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(
            dir.path().join("src/main.rs"),
            "use crate::local::thing;\n",
        )
        .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "serde");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }
}
