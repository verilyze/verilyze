// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision, list_files_with_ext,
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
    let files = match list_files_with_ext(
        context.scan_root,
        context.exclude_dir_names,
        "py",
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
            push_import_roots_from_line(line, &mut roots);
        }
    }
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
        let py_files = match list_files_with_ext(
            context.scan_root,
            context.exclude_dir_names,
            "py",
        ) {
            Ok(files) => files,
            Err(_) => return TierBDecision::Unknown,
        };
        if py_files.is_empty() {
            return TierBDecision::Unknown;
        }
        let roots = collect_python_import_roots(context);
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
}
