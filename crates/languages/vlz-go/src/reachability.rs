// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision, list_files_with_ext,
    note_tier_b_file_read_attempt,
};

#[derive(Debug, Default)]
pub struct GoTierBAnalyzer;

impl GoTierBAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

fn extract_first_quoted_path(line: &str) -> Option<String> {
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            let mut out = String::new();
            for c in chars.by_ref() {
                if c == '"' {
                    return Some(out);
                }
                out.push(c);
            }
        }
    }
    None
}

fn quoted_paths_in_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") {
        return out;
    }
    if trimmed.starts_with("import ") && !trimmed.contains('(') {
        if let Some(p) = extract_first_quoted_path(trimmed) {
            out.push(p);
        }
        return out;
    }
    if let Some(p) = extract_first_quoted_path(trimmed) {
        out.push(p);
    }
    out
}

fn collect_go_import_paths(context: &TierBContext<'_>) -> HashSet<String> {
    let mut paths = HashSet::new();
    let files = list_go_files(context);
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
        let mut in_import_block = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if in_import_block {
                if trimmed.starts_with(')') {
                    in_import_block = false;
                    continue;
                }
                for p in quoted_paths_in_line(line) {
                    paths.insert(p);
                }
                continue;
            }
            if trimmed.starts_with("import ") {
                if trimmed.contains("import (") || trimmed.ends_with('(') {
                    in_import_block = true;
                    continue;
                }
                for p in quoted_paths_in_line(line) {
                    paths.insert(p);
                }
            }
        }
    }
    paths
}

fn go_import_paths_cache() -> &'static Mutex<HashMap<String, HashSet<String>>>
{
    static CACHE: OnceLock<Mutex<HashMap<String, HashSet<String>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn import_paths_cache_key(context: &TierBContext<'_>) -> String {
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

fn cached_go_import_paths(context: &TierBContext<'_>) -> HashSet<String> {
    let key = import_paths_cache_key(context);
    if let Some(cached) = go_import_paths_cache()
        .lock()
        .expect("go import paths cache lock poisoned")
        .get(&key)
        .cloned()
    {
        return cached;
    }
    let paths = collect_go_import_paths(context);
    go_import_paths_cache()
        .lock()
        .expect("go import paths cache lock poisoned")
        .insert(key, paths.clone());
    paths
}

fn module_used(import_paths: &HashSet<String>, module_path: &str) -> bool {
    let module_path = module_path.trim();
    if module_path.is_empty() {
        return false;
    }
    import_paths.iter().any(|import_path| {
        import_path == module_path
            || import_path.starts_with(&format!("{module_path}/"))
    })
}

fn go_module_path_ambiguous(path: &str) -> bool {
    if path.contains("/v0.") {
        return true;
    }
    for segment in path.split('/') {
        if segment.len() > 1
            && segment.starts_with('v')
            && segment[1..].chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    path.chars().filter(|&c| c == '/').count() > 4
}

impl ReachabilityAnalyzer for GoTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "go"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &["Go"]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let go_files = list_go_files(context);
        if go_files.is_empty() {
            return TierBDecision::Unknown;
        }
        let imports = cached_go_import_paths(context);
        if imports.is_empty() {
            return TierBDecision::Unknown;
        }
        if module_used(&imports, &context.package.name) {
            return TierBDecision::Reachable;
        }
        if go_module_path_ambiguous(&context.package.name) {
            TierBDecision::Unknown
        } else {
            TierBDecision::NotReachable
        }
    }
}

fn go_file_cache() -> &'static Mutex<HashMap<String, Vec<PathBuf>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<PathBuf>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn list_go_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
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
    if let Some(cached) = go_file_cache()
        .lock()
        .expect("go reachability cache lock poisoned")
        .get(&cache_key)
        .cloned()
    {
        return cached;
    }
    let mut files = Vec::new();
    for root in roots {
        if let Ok(mut found) =
            list_files_with_ext(&root, context.exclude_dir_names, "go")
        {
            files.append(&mut found);
        }
    }
    go_file_cache()
        .lock()
        .expect("go reachability cache lock poisoned")
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
            ecosystem: Some("Go".to_string()),
        };
        TierBContext {
            scan_root: root,
            exclude_dir_names: Box::leak(Box::new(HashSet::new())),
            package: Box::leak(Box::new(package)),
            language: "go",
            manifest_paths: Box::leak(Box::new(Vec::<PathBuf>::new())),
        }
    }

    #[test]
    fn helper_extract_quoted_path() {
        assert_eq!(
            extract_first_quoted_path("import \"github.com/foo/bar\""),
            Some("github.com/foo/bar".to_string())
        );
        assert_eq!(
            extract_first_quoted_path("import alias \"github.com/foo/bar\""),
            Some("github.com/foo/bar".to_string())
        );
        assert_eq!(extract_first_quoted_path("no quote"), None);
    }

    #[test]
    fn helper_quoted_paths_in_line_variants() {
        assert!(quoted_paths_in_line("// import \"fmt\"").is_empty());
        assert_eq!(
            quoted_paths_in_line("import \"fmt\""),
            vec!["fmt".to_string()]
        );
        assert_eq!(
            quoted_paths_in_line("alias \"github.com/foo/bar\""),
            vec!["github.com/foo/bar".to_string()]
        );
    }

    #[test]
    fn helper_module_used_and_ambiguity() {
        let mut imports = HashSet::new();
        imports.insert("github.com/foo/bar/sub".to_string());
        assert!(module_used(&imports, "github.com/foo/bar"));
        assert!(!module_used(&imports, "  "));
        assert!(go_module_path_ambiguous("example.com/v0.1/mod"));
        assert!(go_module_path_ambiguous("example.com/mod/v2"));
        assert!(!go_module_path_ambiguous("github.com/foo/bar"));
    }

    #[test]
    fn analyze_unknown_when_no_go_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_reachable_when_import_matches_module_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"github.com/foo/bar/sub\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
    }

    #[test]
    fn analyze_not_reachable_when_unambiguous_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"fmt\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }

    #[test]
    fn analyze_unknown_when_module_path_is_ambiguous() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"fmt\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "example.com/mod/v2");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_unknown_when_go_file_has_no_imports() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nfunc main() {}\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_uses_cached_file_enumeration_across_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"github.com/foo/bar/sub\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        reset_tier_b_counters();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
        let (enum_calls, _, read_attempts, _) = snapshot_tier_b_counters();
        assert!(enum_calls == 0 || enum_calls == 1);
        assert!(read_attempts == 0 || read_attempts <= 2);
    }

    #[test]
    fn analyze_scopes_to_manifest_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let in_scope = dir.path().join("service_a");
        let out_scope = dir.path().join("service_b");
        std::fs::create_dir_all(&in_scope).expect("mkdir");
        std::fs::create_dir_all(&out_scope).expect("mkdir");
        let manifest = in_scope.join("go.mod");
        std::fs::write(&manifest, "module example.com/service_a\n")
            .expect("manifest");
        std::fs::write(
            in_scope.join("main.go"),
            "package main\nimport \"fmt\"\n",
        )
        .expect("write");
        std::fs::write(
            out_scope.join("main.go"),
            "package main\nimport \"github.com/foo/bar/sub\"\n",
        )
        .expect("write");
        let package = vlz_db::Package {
            name: "github.com/foo/bar".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("Go".to_string()),
        };
        let ctx = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: Box::leak(Box::new(HashSet::new())),
            package: Box::leak(Box::new(package)),
            language: "go",
            manifest_paths: Box::leak(Box::new(vec![manifest])),
        };
        let analyzer = GoTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }
}
