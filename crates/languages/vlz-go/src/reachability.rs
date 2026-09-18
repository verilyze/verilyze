// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use vlz_reachability_trait::{
    LineCommentStyle, ReachabilityAnalyzer, ReachabilityEvidence,
    TierBContext, TierBDecision, TierCResult, line_code_for_symbol_match,
    list_files_with_ext, note_tier_b_file_read_attempt,
    push_reachability_evidence, qualified_symbol_in_code,
    reachability_evidence_at_cap, tier_c_decision,
};
#[cfg(feature = "tier-d")]
use vlz_reachability_trait::{
    MAX_TIER_D_SOURCE_FILE_BYTES, read_source_if_within_byte_limit,
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
    parse_go_import_spec(line)
        .map(|spec| vec![spec.path])
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoImportLocal {
    Name(String),
    Dot,
    Blank,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoImportSpec {
    pub path: String,
    pub local: GoImportLocal,
}

pub(crate) fn go_default_local_name(import_path: &str) -> String {
    let segs: Vec<&str> =
        import_path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return String::new();
    }
    let last = segs[segs.len() - 1];
    if segs.len() >= 2
        && last.len() > 1
        && last.starts_with('v')
        && last[1..].chars().all(|c| c.is_ascii_digit())
    {
        return segs[segs.len() - 2].to_string();
    }
    last.to_string()
}

pub(crate) fn parse_go_import_spec(line: &str) -> Option<GoImportSpec> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") {
        return None;
    }
    let mut body = trimmed;
    if let Some(rest) = body.strip_prefix("import") {
        let rest = rest.trim_start();
        if rest.starts_with('(') || rest.is_empty() {
            return None;
        }
        body = rest;
    }
    parse_go_import_spec_body(body)
}

fn parse_go_import_spec_body(body: &str) -> Option<GoImportSpec> {
    let path = extract_first_quoted_path(body)?;
    if path.is_empty() {
        return None;
    }
    let before = body.split_once('"')?.0.trim();
    let local = if before.is_empty() {
        GoImportLocal::Name(go_default_local_name(&path))
    } else if before == "." {
        GoImportLocal::Dot
    } else if before == "_" {
        GoImportLocal::Blank
    } else {
        let name = before.split_whitespace().last()?.trim();
        if name.is_empty() {
            GoImportLocal::Name(go_default_local_name(&path))
        } else {
            GoImportLocal::Name(name.to_string())
        }
    };
    Some(GoImportSpec { path, local })
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
        for spec in collect_go_import_specs_from_content(&content) {
            paths.insert(spec.path);
        }
    }
    paths
}

fn collect_go_import_specs_from_content(content: &str) -> Vec<GoImportSpec> {
    let mut specs = Vec::new();
    let mut in_import_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if in_import_block {
            if trimmed.starts_with(')') {
                in_import_block = false;
                continue;
            }
            if let Some(spec) = parse_go_import_spec(line) {
                specs.push(spec);
            }
            continue;
        }
        if trimmed.starts_with("import ") {
            if trimmed.contains("import (") || trimmed.ends_with('(') {
                in_import_block = true;
                continue;
            }
            if let Some(spec) = parse_go_import_spec(line) {
                specs.push(spec);
            }
        }
    }
    specs
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

fn go_import_path_matches(sym: &str, import: &str) -> bool {
    sym == import
        || import.starts_with(&format!("{sym}/"))
        || sym.starts_with(&format!("{import}/"))
}

fn go_line_has_symbol_evidence(line: &str, symbol: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") {
        return false;
    }
    if trimmed.starts_with("import ") {
        for import_path in quoted_paths_in_line(line) {
            if go_import_path_matches(symbol, &import_path) {
                return true;
            }
        }
        return false;
    }
    let code =
        line_code_for_symbol_match(trimmed, LineCommentStyle::SlashSlash);
    qualified_symbol_in_code(&code, symbol)
}

fn collect_go_symbol_evidence(
    files: &[PathBuf],
    symbol: &str,
    imports: &HashSet<String>,
) -> Vec<ReachabilityEvidence> {
    let mut evidence = Vec::new();
    'files: for path in files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if !imports.iter().any(|imp| content.contains(imp.as_str())) {
            continue;
        }
        for (idx, line) in content.lines().enumerate() {
            if go_line_has_symbol_evidence(line, symbol) {
                push_reachability_evidence(
                    &mut evidence,
                    path.clone(),
                    (idx + 1) as u32,
                    symbol,
                );
            }
            if reachability_evidence_at_cap(&evidence) {
                break 'files;
            }
        }
    }
    evidence
}

fn collect_go_import_path_evidence(
    files: &[PathBuf],
    sym: &str,
) -> Vec<ReachabilityEvidence> {
    let mut evidence = Vec::new();
    'files: for path in files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for (idx, line) in content.lines().enumerate() {
            for import_path in quoted_paths_in_line(line) {
                if go_import_path_matches(sym, &import_path) {
                    push_reachability_evidence(
                        &mut evidence,
                        path.clone(),
                        (idx + 1) as u32,
                        sym,
                    );
                }
            }
            if reachability_evidence_at_cap(&evidence) {
                break 'files;
            }
        }
    }
    evidence
}

fn tier_c_result_for_symbols(
    context: &TierBContext<'_>,
    advisory_symbols: &[String],
) -> TierCResult {
    let imports = cached_go_import_paths(context);
    let sources_present = !imports.is_empty();
    let files = list_go_files(context);
    let mut evidence = Vec::new();
    for sym in advisory_symbols {
        if sym.contains('/') {
            for item in collect_go_import_path_evidence(&files, sym) {
                push_reachability_evidence(
                    &mut evidence,
                    item.path,
                    item.start_line,
                    item.symbol,
                );
            }
        } else {
            for item in collect_go_symbol_evidence(&files, sym, &imports) {
                push_reachability_evidence(
                    &mut evidence,
                    item.path,
                    item.start_line,
                    item.symbol,
                );
            }
        }
    }
    let decision = tier_c_decision(
        !evidence.is_empty(),
        sources_present,
        false,
        go_module_path_ambiguous(&context.package.name),
    );
    TierCResult { decision, evidence }
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

    fn supports_tier_c(&self) -> bool {
        true
    }

    fn analyze_tier_c(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCResult {
        tier_c_result_for_symbols(context, advisory_symbols)
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
                selector_match_lines, symbol_import_path, trailing_go_ident,
            };
            use vlz_reachability_trait::TierCDecision;
            let files = list_go_files(context);
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
                let specs = collect_go_import_specs_from_content(&content);
                for sym in advisory_symbols {
                    let Some(ident) = trailing_go_ident(sym) else {
                        continue;
                    };
                    let symbol_import = symbol_import_path(sym);
                    let mut locals = Vec::new();
                    let mut unresolved = false;
                    for spec in &specs {
                        if !go_import_path_matches(
                            &context.package.name,
                            &spec.path,
                        ) && !symbol_import.is_some_and(|p| {
                            go_import_path_matches(p, &spec.path)
                        }) {
                            continue;
                        }
                        match &spec.local {
                            GoImportLocal::Dot | GoImportLocal::Blank => {
                                unresolved = true;
                            }
                            GoImportLocal::Name(name) if !name.is_empty() => {
                                locals.push(name.clone());
                            }
                            GoImportLocal::Name(_) => {}
                        }
                    }
                    if unresolved {
                        continue;
                    }
                    for line in selector_match_lines(&content, &locals, ident)
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
            let decision = if !evidence.is_empty() {
                TierCDecision::Reachable
            } else {
                TierCDecision::Unknown
            };
            TierCResult { decision, evidence }
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
    use vlz_reachability_trait::TierCDecision;
    #[cfg(feature = "perf-instrumentation")]
    use vlz_reachability_trait::measure_tier_b_counters;

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
    fn helper_parse_go_import_spec_alias_dot_blank() {
        let aliased =
            parse_go_import_spec("import alias \"github.com/foo/bar\"")
                .expect("spec");
        assert_eq!(aliased.path, "github.com/foo/bar");
        assert_eq!(aliased.local, GoImportLocal::Name("alias".to_string()));
        assert_eq!(
            parse_go_import_spec("import . \"fmt\"").expect("dot").local,
            GoImportLocal::Dot
        );
        assert_eq!(
            parse_go_import_spec("import _ \"fmt\"")
                .expect("blank")
                .local,
            GoImportLocal::Blank
        );
        assert_eq!(go_default_local_name("github.com/foo/bar/v2"), "bar");
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

    #[cfg(feature = "perf-instrumentation")]
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
        let (_, (enum_calls, _, read_attempts, _)) =
            measure_tier_b_counters(|| {
                assert_eq!(
                    analyzer.analyze_tier_b(&ctx),
                    TierBDecision::Reachable
                );
                assert_eq!(
                    analyzer.analyze_tier_b(&ctx),
                    TierBDecision::Reachable
                );
            });
        assert_eq!(enum_calls, 1);
        assert_eq!(read_attempts, 1);
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

    #[test]
    fn analyze_tier_c_reachable_for_matching_import_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"github.com/foo/bar/sub\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        assert_eq!(
            analyzer
                .analyze_tier_c(&ctx, &["github.com/foo/bar/sub".to_string()])
                .decision,
            TierCDecision::Reachable
        );
    }

    #[test]
    fn analyze_tier_c_not_reachable_for_unrelated_import_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"fmt\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        assert_eq!(
            analyzer
                .analyze_tier_c(&ctx, &["github.com/foo/bar/sub".to_string()])
                .decision,
            TierCDecision::NotReachable
        );
    }

    #[test]
    fn analyze_tier_c_reachable_for_symbol_reference() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"github.com/foo/bar\"\nfunc main() { bar.VulnFn() }\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        let result = analyzer.analyze_tier_c(&ctx, &["VulnFn".to_string()]);
        assert_eq!(result.decision, TierCDecision::Reachable);
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].start_line, 3);
        assert_eq!(result.evidence[0].symbol, "VulnFn");
    }

    #[test]
    fn analyze_tier_c_no_evidence_for_unrelated_quoted_import() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"fmt\"\nimport \"github.com/foo/bar\"\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        let result = analyzer
            .analyze_tier_c(&ctx, &["github.com/other/pkg".to_string()]);
        assert!(result.evidence.is_empty());
    }

    #[cfg(feature = "tier-d")]
    #[test]
    fn analyze_tier_d_reachable_for_aliased_import() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport alias \"github.com/foo/bar\"\nfunc main() { alias.Vuln() }\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        let result = analyzer
            .analyze_tier_d(&ctx, &["github.com/foo/bar.Vuln".to_string()]);
        assert!(analyzer.supports_tier_d());
        assert_eq!(result.decision, TierCDecision::Reachable);
        assert!(!result.evidence.is_empty());
    }

    #[cfg(feature = "tier-d")]
    #[test]
    fn analyze_tier_d_unknown_for_dot_import() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport . \"github.com/foo/bar\"\nfunc main() { Vuln() }\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        let result = analyzer
            .analyze_tier_d(&ctx, &["github.com/foo/bar.Vuln".to_string()]);
        assert_eq!(result.decision, TierCDecision::Unknown);
        assert_ne!(result.decision, TierCDecision::NotReachable);
    }

    #[cfg(feature = "tier-d")]
    #[test]
    fn analyze_tier_d_unknown_for_blank_import() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport _ \"github.com/foo/bar\"\nfunc main() {}\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        let result = analyzer
            .analyze_tier_d(&ctx, &["github.com/foo/bar.Vuln".to_string()]);
        assert_eq!(result.decision, TierCDecision::Unknown);
    }

    #[cfg(feature = "tier-d")]
    #[test]
    fn analyze_tier_d_unknown_for_comment_or_string() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"github.com/foo/bar\"\nfunc main() {\n  // bar.Vuln\n  s := \"bar.Vuln\"\n}\n",
        )
        .expect("write");
        let analyzer = GoTierBAnalyzer::new();
        let ctx = context_for(dir.path(), "github.com/foo/bar");
        let result = analyzer
            .analyze_tier_d(&ctx, &["github.com/foo/bar.Vuln".to_string()]);
        assert_eq!(result.decision, TierCDecision::Unknown);
    }
}
