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
pub struct PythonTierBAnalyzer;

impl PythonTierBAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

fn normalize_pypi_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

fn first_segment(module_path: &str) -> Option<String> {
    let s = module_path.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.split('.').next().unwrap_or("").to_string())
}

fn pypi_name_is_ambiguous(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if name.chars().any(|c| c.is_ascii_uppercase()) {
        return true;
    }
    if lower.chars().any(|c| c.is_ascii_digit()) {
        return true;
    }
    if lower.contains('-') {
        return true;
    }
    false
}

fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn push_import_roots_from_line(line: &str, roots: &mut HashSet<String>) {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return;
    }
    if let Some(rest) = t.strip_prefix("import ") {
        for part in split_top_level_commas(rest) {
            let part = part.trim();
            let name = part.split_whitespace().next().unwrap_or("").trim();
            if name.is_empty() || name == "as" {
                continue;
            }
            if let Some(seg) = first_segment(name) {
                roots.insert(normalize_pypi_name(&seg));
            }
        }
        return;
    }
    if let Some(rest) = t.strip_prefix("from ") {
        let rest = rest.trim_start();
        if rest == "import" || rest.starts_with("import ") {
            return;
        }
        let Some(space_pos) = rest.find(" import ") else {
            return;
        };
        let from_part = rest[..space_pos].trim();
        if from_part == "." || from_part == ".." {
            return;
        }
        if let Some(seg) = first_segment(from_part) {
            roots.insert(normalize_pypi_name(&seg));
        }
    }
}

fn collect_python_import_roots(context: &TierBContext<'_>) -> HashSet<String> {
    let mut roots = HashSet::new();
    let files = list_python_files(context);
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
            push_import_roots_from_line(line, &mut roots);
        }
    }
    roots
}

fn python_import_roots_cache()
-> &'static Mutex<HashMap<String, HashSet<String>>> {
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

fn cached_python_import_roots(context: &TierBContext<'_>) -> HashSet<String> {
    let key = import_roots_cache_key(context);
    if let Some(cached) = python_import_roots_cache()
        .lock()
        .expect("python import roots cache lock poisoned")
        .get(&key)
        .cloned()
    {
        return cached;
    }
    let roots = collect_python_import_roots(context);
    python_import_roots_cache()
        .lock()
        .expect("python import roots cache lock poisoned")
        .insert(key, roots.clone());
    roots
}

impl ReachabilityAnalyzer for PythonTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "python"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &["PyPI"]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let py_files = list_python_files(context);
        if py_files.is_empty() {
            return TierBDecision::Unknown;
        }
        let roots = cached_python_import_roots(context);
        if roots.is_empty() {
            return TierBDecision::Unknown;
        }
        let normalized = normalize_pypi_name(&context.package.name);
        if roots.contains(&normalized) {
            return TierBDecision::Reachable;
        }
        if pypi_name_is_ambiguous(&context.package.name) {
            TierBDecision::Unknown
        } else {
            TierBDecision::NotReachable
        }
    }
}

fn python_file_cache() -> &'static Mutex<HashMap<String, Vec<PathBuf>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<PathBuf>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn list_python_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
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
    if let Some(cached) = python_file_cache()
        .lock()
        .expect("python reachability cache lock poisoned")
        .get(&cache_key)
        .cloned()
    {
        return cached;
    }
    let mut files = Vec::new();
    for root in roots {
        if let Ok(mut found) =
            list_files_with_ext(&root, context.exclude_dir_names, "py")
        {
            files.append(&mut found);
        }
    }
    python_file_cache()
        .lock()
        .expect("python reachability cache lock poisoned")
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
            ecosystem: Some("PyPI".to_string()),
        };
        TierBContext {
            scan_root: root,
            exclude_dir_names: Box::leak(Box::new(HashSet::new())),
            package: Box::leak(Box::new(package)),
            language: "python",
            manifest_paths: Box::leak(Box::new(Vec::<PathBuf>::new())),
        }
    }

    #[test]
    fn helper_normalize_and_first_segment() {
        assert_eq!(normalize_pypi_name("google-auth"), "google_auth");
        assert_eq!(first_segment("a.b.c"), Some("a".to_string()));
        assert_eq!(first_segment("  "), None);
    }

    #[test]
    fn helper_ambiguity_rules() {
        assert!(pypi_name_is_ambiguous("Requests"));
        assert!(pypi_name_is_ambiguous("urllib3"));
        assert!(pypi_name_is_ambiguous("google-auth"));
        assert!(!pypi_name_is_ambiguous("requests"));
    }

    #[test]
    fn helper_split_top_level_commas_nested() {
        let parts = split_top_level_commas("a, b(c, d), e");
        assert_eq!(parts, vec!["a", " b(c, d)", " e"]);
    }

    #[test]
    fn helper_line_parsing_import_and_from() {
        let mut roots = HashSet::new();
        push_import_roots_from_line(
            "import requests, urllib.parse",
            &mut roots,
        );
        push_import_roots_from_line(
            "from packaging.version import Version",
            &mut roots,
        );
        push_import_roots_from_line("from . import local", &mut roots);
        push_import_roots_from_line("from .. import parent", &mut roots);
        push_import_roots_from_line("from import x", &mut roots);
        assert!(roots.contains("requests"));
        assert!(roots.contains("urllib"));
        assert!(roots.contains("packaging"));
        assert!(!roots.contains("local"));
        assert!(!roots.contains("parent"));
    }

    #[test]
    fn analyze_unknown_when_no_python_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let analyzer = PythonTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "requests");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_reachable_when_direct_import_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "import requests\n")
            .expect("write");
        let analyzer = PythonTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "requests");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
    }

    #[test]
    fn analyze_not_reachable_when_unambiguous_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "import sys\n")
            .expect("write");
        let analyzer = PythonTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "requests");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }

    #[test]
    fn analyze_unknown_when_package_name_is_ambiguous() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "import sys\n")
            .expect("write");
        let analyzer = PythonTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "urllib3");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_unknown_when_python_file_has_no_imports() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "# comments only\nx = 1\n")
            .expect("write");
        let analyzer = PythonTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "requests");
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Unknown);
    }

    #[test]
    fn analyze_uses_cached_file_enumeration_across_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "import requests\n")
            .expect("write");
        let analyzer = PythonTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "requests");
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
        let in_scope = dir.path().join("service_a");
        let out_scope = dir.path().join("service_b");
        std::fs::create_dir_all(&in_scope).expect("mkdir");
        std::fs::create_dir_all(&out_scope).expect("mkdir");
        let manifest = in_scope.join("requirements.txt");
        std::fs::write(&manifest, "requests==2.0.0\n").expect("manifest");
        std::fs::write(in_scope.join("app.py"), "import sys\n")
            .expect("write");
        std::fs::write(out_scope.join("app.py"), "import requests\n")
            .expect("write");
        let package = vlz_db::Package {
            name: "requests".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some("PyPI".to_string()),
        };
        let ctx = TierBContext {
            scan_root: dir.path(),
            exclude_dir_names: Box::leak(Box::new(HashSet::new())),
            package: Box::leak(Box::new(package)),
            language: "python",
            manifest_paths: Box::leak(Box::new(vec![manifest])),
        };
        let analyzer = PythonTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }
}
