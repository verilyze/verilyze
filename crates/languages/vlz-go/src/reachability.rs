// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision, list_files_with_ext,
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
    let files = match list_files_with_ext(
        context.scan_root,
        context.exclude_dir_names,
        "go",
    ) {
        Ok(files) => files,
        Err(_) => return paths,
    };
    for path in files {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
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
        let go_files = match list_files_with_ext(
            context.scan_root,
            context.exclude_dir_names,
            "go",
        ) {
            Ok(files) => files,
            Err(_) => return TierBDecision::Unknown,
        };
        if go_files.is_empty() {
            return TierBDecision::Unknown;
        }
        let imports = collect_go_import_paths(context);
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
}
