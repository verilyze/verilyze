// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use vlz_db::CRATES_IO_ECOSYSTEM;

use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision, TierCDecision,
    list_files_with_ext, note_tier_b_file_read_attempt,
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
    let files = list_rust_files(context);
    for path in files {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => {
                note_tier_b_file_read_attempt(true);
                c
            }
            Err(_) => {
                note_tier_b_file_read_attempt(false);
                continue;
            }
        };
        for line in content.lines() {
            for r in crate_roots_from_line(line) {
                roots.insert(r);
            }
        }
    }
    roots
}

fn collect_rust_use_prefixes(context: &TierBContext<'_>) -> HashSet<String> {
    let mut prefixes = HashSet::new();
    for path in list_rust_files(context) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            prefixes.extend(rust_use_prefixes_from_line(line));
        }
    }
    prefixes
}

fn rust_use_prefixes_from_line(line: &str) -> Vec<String> {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix("use ") else {
        return Vec::new();
    };
    let rest = rest.trim_start();
    if let Some(inner) = rest
        .strip_prefix('{')
        .and_then(|r| r.split_once('}'))
        .map(|(a, _)| a)
    {
        return inner
            .split(',')
            .filter_map(|part| rust_use_path_from_part(part.trim()))
            .collect();
    }
    if rest.starts_with('{') {
        return Vec::new();
    }
    rest.split(',')
        .filter_map(|part| rust_use_path_from_part(part.trim()))
        .collect()
}

fn rust_use_path_from_part(part: &str) -> Option<String> {
    let part = part.trim().trim_start_matches("::");
    if part.is_empty() {
        return None;
    }
    let path = part.split(" as ").next()?.trim();
    if path.is_empty()
        || skip_first_segment(path.split("::").next().unwrap_or(""))
    {
        return None;
    }
    Some(path.to_string())
}

fn rust_symbol_matches_use_prefixes(
    sym: &str,
    prefixes: &HashSet<String>,
) -> bool {
    let norm_sym = normalize_crate_name(sym);
    for prefix in prefixes {
        let norm_prefix = normalize_crate_name(prefix);
        if norm_sym == norm_prefix
            || norm_sym.starts_with(&format!("{norm_prefix}::"))
            || norm_prefix.starts_with(&format!("{norm_sym}::"))
        {
            return true;
        }
        if let Some((sym_mod, _)) = norm_sym.rsplit_once("::")
            && (norm_prefix == sym_mod
                || norm_prefix.starts_with(&format!("{sym_mod}::")))
        {
            return true;
        }
    }
    false
}

fn rust_import_roots_cache() -> &'static Mutex<HashMap<String, HashSet<String>>>
{
    static CACHE: OnceLock<Mutex<HashMap<String, HashSet<String>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn rust_use_prefixes_cache() -> &'static Mutex<HashMap<String, HashSet<String>>>
{
    static CACHE: OnceLock<Mutex<HashMap<String, HashSet<String>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn import_roots_cache_key(context: &TierBContext<'_>) -> String {
    let roots = scoped_roots(context);
    format!(
        "{}|{}",
        context.scan_root.display(),
        roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(";")
    )
}

fn cached_rust_use_prefixes(context: &TierBContext<'_>) -> HashSet<String> {
    let key = import_roots_cache_key(context);
    if let Some(cached) = rust_use_prefixes_cache()
        .lock()
        .expect("rust use prefixes cache lock poisoned")
        .get(&key)
        .cloned()
    {
        return cached;
    }
    let prefixes = collect_rust_use_prefixes(context);
    rust_use_prefixes_cache()
        .lock()
        .expect("rust use prefixes cache lock poisoned")
        .insert(key, prefixes.clone());
    prefixes
}

fn cached_rust_import_roots(context: &TierBContext<'_>) -> HashSet<String> {
    let key = import_roots_cache_key(context);
    if let Some(cached) = rust_import_roots_cache()
        .lock()
        .expect("rust import roots cache lock poisoned")
        .get(&key)
        .cloned()
    {
        return cached;
    }
    let roots = collect_rust_import_roots(context);
    rust_import_roots_cache()
        .lock()
        .expect("rust import roots cache lock poisoned")
        .insert(key, roots.clone());
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
        &[CRATES_IO_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let rs_files = list_rust_files(context);
        if rs_files.is_empty() {
            return TierBDecision::Unknown;
        }
        let roots = cached_rust_import_roots(context);
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

    fn supports_tier_c(&self) -> bool {
        true
    }

    fn analyze_tier_c(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCDecision {
        let prefixes = cached_rust_use_prefixes(context);
        if prefixes.is_empty() {
            return TierCDecision::Unknown;
        }
        for sym in advisory_symbols {
            if rust_symbol_matches_use_prefixes(sym, &prefixes) {
                return TierCDecision::Reachable;
            }
        }
        if rust_name_allows_confident_absence(&context.package.name) {
            TierCDecision::NotReachable
        } else {
            TierCDecision::Unknown
        }
    }
}

fn rust_file_cache() -> &'static Mutex<HashMap<String, Vec<PathBuf>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<PathBuf>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn list_rust_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let roots = scoped_roots(context);
    let cache_key = format!(
        "{}|{}",
        context.scan_root.display(),
        roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(";")
    );
    if let Some(cached) = rust_file_cache()
        .lock()
        .expect("rust reachability cache lock poisoned")
        .get(&cache_key)
        .cloned()
    {
        return cached;
    }
    let mut files = Vec::new();
    for root in roots {
        if let Ok(mut found) =
            list_files_with_ext(&root, context.exclude_dir_names, "rs")
        {
            files.append(&mut found);
        }
    }
    rust_file_cache()
        .lock()
        .expect("rust reachability cache lock poisoned")
        .insert(cache_key, files.clone());
    files
}

fn scoped_roots(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = context
        .manifest_paths
        .iter()
        .filter_map(|manifest| manifest.parent().map(Path::to_path_buf))
        .collect();
    if roots.is_empty() {
        return vec![context.scan_root.to_path_buf()];
    }
    roots.sort();
    roots.dedup();
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use vlz_reachability_trait::{
        reset_tier_b_counters, snapshot_tier_b_counters,
    };

    fn context_for<'a>(
        root: &'a std::path::Path,
        package_name: &str,
    ) -> TierBContext<'a> {
        let package = vlz_db::Package {
            name: package_name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
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

    #[test]
    fn analyze_uses_cached_file_enumeration_across_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "use serde::Deserialize;\n",
        )
        .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "serde");
        reset_tier_b_counters();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
        let (enum_calls, _, read_attempts, _) = snapshot_tier_b_counters();
        assert!(enum_calls == 0 || enum_calls == 1);
        assert!(read_attempts == 0 || read_attempts == 1);
    }

    #[test]
    fn analyze_scopes_to_manifest_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let in_scope = dir.path().join("crate_a");
        let out_scope = dir.path().join("crate_b");
        std::fs::create_dir_all(in_scope.join("src")).expect("mkdir");
        std::fs::create_dir_all(out_scope.join("src")).expect("mkdir");
        let manifest = in_scope.join("Cargo.toml");
        std::fs::write(
            &manifest,
            "[package]\nname=\"a\"\nversion=\"0.1.0\"\n",
        )
        .expect("manifest");
        std::fs::write(in_scope.join("src/lib.rs"), "use std::fmt;\n")
            .expect("write");
        std::fs::write(
            out_scope.join("src/lib.rs"),
            "use serde::Deserialize;\n",
        )
        .expect("write");
        let package = vlz_db::Package {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some(CRATES_IO_ECOSYSTEM.to_string()),
        };
        let ctx = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: Box::leak(Box::new(HashSet::new())),
            package: Box::leak(Box::new(package)),
            language: "rust",
            manifest_paths: Box::leak(Box::new(vec![manifest])),
        };
        let analyzer = RustTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }

    #[test]
    fn analyze_tier_c_reachable_for_matching_use_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(dir.path().join("src/main.rs"), "use http::a::Vuln;\n")
            .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "http");
        assert_eq!(
            analyzer.analyze_tier_c(&ctx, &["http::a::vuln".to_string()]),
            TierCDecision::Reachable
        );
    }

    #[test]
    fn analyze_tier_c_not_reachable_for_different_module_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(dir.path().join("src/main.rs"), "use http::a::Vuln;\n")
            .expect("write");
        let analyzer = RustTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "http");
        assert_eq!(
            analyzer.analyze_tier_c(&ctx, &["http::b::safe".to_string()]),
            TierCDecision::NotReachable
        );
    }
}
