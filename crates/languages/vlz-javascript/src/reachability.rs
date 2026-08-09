// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use vlz_db::NPM_ECOSYSTEM;
use vlz_reachability_trait::{
    LineCommentStyle, ReachabilityAnalyzer, TierBContext, TierBDecision,
    TierCDecision, TierCResult, line_code_for_symbol_match,
    list_files_with_ext, note_tier_b_file_read_attempt,
    push_reachability_evidence, qualified_symbol_in_code,
    reachability_evidence_at_cap,
};

/// Source extensions for JavaScript and TypeScript.
const JS_TS_EXTS: &[&str] =
    &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];

/// Tier B reachability for npm packages via import/require scanning.
#[derive(Debug, Default)]
pub struct JsTierBAnalyzer;

impl JsTierBAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self
    }
}

fn list_js_ts_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scoped_roots(context) {
        for ext in JS_TS_EXTS {
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

fn scoped_roots(context: &TierBContext<'_>) -> Vec<PathBuf> {
    if context.manifest_paths.is_empty() {
        return vec![context.scan_root.to_path_buf()];
    }
    let mut roots: Vec<PathBuf> = context
        .manifest_paths
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();
    roots.sort();
    roots.dedup();
    if roots.is_empty() {
        vec![context.scan_root.to_path_buf()]
    } else {
        roots
    }
}

/// Extract package name from an import specifier (`lodash`, `@scope/pkg/sub`).
pub fn package_name_from_specifier(spec: &str) -> Option<String> {
    let s = spec
        .trim()
        .trim_matches(|c| c == '\'' || c == '"' || c == '`');
    if s.is_empty() || s.starts_with('.') || s.starts_with('/') {
        return None;
    }
    // node builtins
    if !s.starts_with('@') && !s.contains('/') {
        return Some(s.to_string());
    }
    if let Some(rest) = s.strip_prefix('@') {
        let mut parts = rest.splitn(2, '/');
        let scope = parts.next()?;
        let name = parts.next()?.split('/').next()?;
        return Some(format!("@{scope}/{name}"));
    }
    Some(s.split('/').next()?.to_string())
}

fn import_spec_patterns() -> &'static [regex::Regex] {
    static PATTERNS: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // from 'pkg' / from "pkg" (covers multiline ESM and export-from)
            regex::Regex::new(r#"(?i)\bfrom\s+['"]([^'"]+)['"]"#)
                .expect("from import regex"),
            // require('pkg') / require("pkg")
            regex::Regex::new(r#"(?i)\brequire\s*\(\s*['"]([^'"]+)['"]"#)
                .expect("require regex"),
            // import('pkg') dynamic import
            regex::Regex::new(r#"(?i)\bimport\s*\(\s*['"]([^'"]+)['"]"#)
                .expect("dynamic import regex"),
            // import 'pkg' side-effect import
            regex::Regex::new(r#"(?i)\bimport\s+['"]([^'"]+)['"]"#)
                .expect("side-effect import regex"),
        ]
    })
}

/// Extract package import/require/from specifiers from source text.
fn import_specs_from_content(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for re in import_spec_patterns() {
        for caps in re.captures_iter(content) {
            if let Some(m) = caps.get(1) {
                out.push(m.as_str().to_string());
            }
        }
    }
    out
}

fn collect_imported_packages(context: &TierBContext<'_>) -> HashSet<String> {
    let mut pkgs = HashSet::new();
    for path in list_js_ts_files(context) {
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
        for spec in import_specs_from_content(&content) {
            if let Some(name) = package_name_from_specifier(&spec) {
                pkgs.insert(name);
            }
        }
    }
    pkgs
}

fn import_cache() -> &'static Mutex<HashMap<String, HashSet<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, HashSet<String>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key(context: &TierBContext<'_>) -> String {
    let roots = scoped_roots(context);
    let mut excludes: Vec<&str> = context
        .exclude_dir_names
        .iter()
        .map(String::as_str)
        .collect();
    excludes.sort_unstable();
    format!(
        "{}|{}|{}",
        context.scan_root.display(),
        roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(";"),
        excludes.join(",")
    )
}

fn cached_imports(context: &TierBContext<'_>) -> HashSet<String> {
    let key = cache_key(context);
    if let Some(cached) = import_cache()
        .lock()
        .expect("js import cache lock")
        .get(&key)
        .cloned()
    {
        return cached;
    }
    let pkgs = collect_imported_packages(context);
    import_cache()
        .lock()
        .expect("js import cache lock")
        .insert(key, pkgs.clone());
    pkgs
}

fn package_ambiguous(name: &str) -> bool {
    // Very short names are ambiguous for text matching.
    name.len() < 2
}

impl ReachabilityAnalyzer for JsTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "javascript"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &[NPM_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let imports = cached_imports(context);
        let name = context.package.name.as_str();
        if package_ambiguous(name) {
            return TierBDecision::Unknown;
        }
        if imports.contains(name) {
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
        let imports = cached_imports(context);
        let files = list_js_ts_files(context);
        let mut evidence = Vec::new();
        let mut saw = false;
        for sym in advisory_symbols {
            if let Some(pkg) = package_name_from_specifier(sym)
                && imports.contains(&pkg)
            {
                saw = true;
            }
            for path in &files {
                let Ok(content) = std::fs::read_to_string(path) else {
                    continue;
                };
                for (idx, line) in content.lines().enumerate() {
                    let code = line_code_for_symbol_match(
                        line.trim(),
                        LineCommentStyle::SlashSlash,
                    );
                    if qualified_symbol_in_code(&code, sym)
                        || import_specs_from_content(line).iter().any(|s| {
                            s == sym
                                || package_name_from_specifier(s).as_deref()
                                    == Some(sym.as_str())
                        })
                    {
                        saw = true;
                        push_reachability_evidence(
                            &mut evidence,
                            path.clone(),
                            (idx + 1) as u32,
                            sym,
                        );
                    }
                    if reachability_evidence_at_cap(&evidence) {
                        break;
                    }
                }
            }
        }
        let decision = if saw {
            TierCDecision::Reachable
        } else if package_ambiguous(&context.package.name) {
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
    use vlz_db::Package;

    #[test]
    fn package_name_from_specifier_scoped_and_subpath() {
        assert_eq!(
            package_name_from_specifier("lodash"),
            Some("lodash".into())
        );
        assert_eq!(
            package_name_from_specifier("lodash/fp"),
            Some("lodash".into())
        );
        assert_eq!(
            package_name_from_specifier("@scope/pkg/utils"),
            Some("@scope/pkg".into())
        );
        assert_eq!(package_name_from_specifier("./local"), None);
    }

    #[test]
    fn tier_b_detects_import() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("app.js"),
            "import _ from 'lodash';\nconsole.log(_);\n",
        )
        .unwrap();
        std::fs::write(tmp.join("package.json"), r#"{"name":"app"}"#).unwrap();
        let pkg = Package {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: Some(NPM_ECOSYSTEM.into()),
        };
        let exclude = Box::leak(Box::new(HashSet::new()));
        let manifests = Box::leak(Box::new(vec![tmp.join("package.json")]));
        let ctx = TierBContext {
            package: &pkg,
            scan_root: tmp,
            exclude_dir_names: exclude,
            language: "javascript",
            manifest_paths: manifests,
        };
        let analyzer = JsTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
    }

    #[test]
    fn tier_b_detects_multiline_from_import() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("app.js"),
            "import {\n  map\n} from 'lodash';\n",
        )
        .unwrap();
        let pkg = Package {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: Some(NPM_ECOSYSTEM.into()),
        };
        let exclude = Box::leak(Box::new(HashSet::new()));
        let manifests = Box::leak(Box::new(Vec::<PathBuf>::new()));
        let ctx = TierBContext {
            package: &pkg,
            scan_root: tmp,
            exclude_dir_names: exclude,
            language: "javascript",
            manifest_paths: manifests,
        };
        let analyzer = JsTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::Reachable);
    }

    #[test]
    fn tier_b_ignores_export_string_literal_false_positive() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(
            tmp.join("app.js"),
            "export const hint = \"lodash\";\n",
        )
        .unwrap();
        let pkg = Package {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: Some(NPM_ECOSYSTEM.into()),
        };
        let exclude = Box::leak(Box::new(HashSet::new()));
        let manifests = Box::leak(Box::new(Vec::<PathBuf>::new()));
        let ctx = TierBContext {
            package: &pkg,
            scan_root: tmp,
            exclude_dir_names: exclude,
            language: "javascript",
            manifest_paths: manifests,
        };
        let analyzer = JsTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }

    #[test]
    fn cache_key_includes_exclude_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let pkg = Package {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: Some(NPM_ECOSYSTEM.into()),
        };
        let empty = Box::leak(Box::new(HashSet::new()));
        let with_exclude =
            Box::leak(Box::new(HashSet::from(["vendor".into()])));
        let manifests = Box::leak(Box::new(Vec::<PathBuf>::new()));
        let ctx_a = TierBContext {
            package: &pkg,
            scan_root: tmp,
            exclude_dir_names: empty,
            language: "javascript",
            manifest_paths: manifests,
        };
        let ctx_b = TierBContext {
            package: &pkg,
            scan_root: tmp,
            exclude_dir_names: with_exclude,
            language: "javascript",
            manifest_paths: manifests,
        };
        assert_ne!(cache_key(&ctx_a), cache_key(&ctx_b));
    }

    #[test]
    fn tier_b_not_reachable_without_import() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        std::fs::write(tmp.join("app.ts"), "export const x = 1;\n").unwrap();
        let pkg = Package {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: Some(NPM_ECOSYSTEM.into()),
        };
        let exclude = Box::leak(Box::new(HashSet::new()));
        let manifests = Box::leak(Box::new(Vec::<PathBuf>::new()));
        let ctx = TierBContext {
            package: &pkg,
            scan_root: tmp,
            exclude_dir_names: exclude,
            language: "javascript",
            manifest_paths: manifests,
        };
        let analyzer = JsTierBAnalyzer::new();
        assert_eq!(analyzer.analyze_tier_b(&ctx), TierBDecision::NotReachable);
    }
}
