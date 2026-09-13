// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use vlz_db::MAVEN_ECOSYSTEM;
use vlz_reachability_trait::{
    LineCommentStyle, ReachabilityAnalyzer, TierBContext, TierBDecision,
    TierCDecision, TierCResult, line_code_for_symbol_match,
    list_files_with_ext, note_tier_b_file_read_attempt,
    push_reachability_evidence, qualified_symbol_in_code,
    reachability_evidence_at_cap, scrub_c_style_comments,
};

use crate::coordinate::is_generic_artifact_id;

const JAVA_KT_EXTS: &[&str] = &["java", "kt"];

/// Extra dirs skipped during Java/Kotlin source walks (build caches).
const JAVA_EXTRA_EXCLUDE_DIRS: &[&str] = &[".gradle"];

#[derive(Debug, Default)]
pub struct JavaTierBAnalyzer;

impl JavaTierBAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

/// Cached first-party Java/Kotlin sources for a scan scope.
///
/// `scrubbed_files` stores comment-scrubbed lines so Tier B FQCN scans and
/// Tier C symbol scans do not re-read or re-scrub the same files per package.
#[derive(Clone, Default)]
struct JavaSourceIndex {
    imports: HashSet<String>,
    scrubbed_files: Vec<(PathBuf, Vec<String>)>,
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

fn merged_excludes(context: &TierBContext<'_>) -> HashSet<String> {
    let mut excludes = context.exclude_dir_names.clone();
    for name in JAVA_EXTRA_EXCLUDE_DIRS {
        excludes.insert((*name).to_string());
    }
    excludes
}

fn list_java_kt_files(
    context: &TierBContext<'_>,
    excludes: &HashSet<String>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scoped_roots(context) {
        for ext in JAVA_KT_EXTS {
            if let Ok(mut found) = list_files_with_ext(&root, excludes, ext) {
                files.append(&mut found);
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn source_index_cache() -> &'static Mutex<HashMap<String, JavaSourceIndex>> {
    static CACHE: OnceLock<Mutex<HashMap<String, JavaSourceIndex>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key(context: &TierBContext<'_>) -> String {
    let roots = scoped_roots(context);
    let excludes = merged_excludes(context);
    let mut exclude_names: Vec<&str> =
        excludes.iter().map(String::as_str).collect();
    exclude_names.sort_unstable();
    format!(
        "{}|{}|{}",
        context.scan_root.display(),
        roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(";"),
        exclude_names.join(",")
    )
}

/// GroupId and its parent when multi-segment (e.g. Guava `com.google.guava`
/// also matches Java packages under `com.google.common`).
///
/// Parent-prefix matching is intentional for Maven coordinates whose groupId
/// does not equal the Java package root. Sibling libraries under the same
/// parent (e.g. Gson vs Guava) can share that prefix; prefer Unknown over a
/// false NotReachable when that ambiguity matters, but keep Reachable on
/// parent matches so Guava-style packages remain detectable.
fn group_import_prefixes(group: &str) -> Vec<String> {
    let mut out = vec![group.to_string()];
    if let Some(idx) = group.rfind('.') {
        let parent = &group[..idx];
        if parent.contains('.') {
            out.push(parent.to_string());
        }
    }
    out
}

fn is_java_id_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// True when `name` appears as a Java type/FQCN fragment in `code`.
fn java_name_in_code(code: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut start = 0usize;
    while let Some(pos) = code[start..].find(name) {
        let idx = start + pos;
        let before_ok = idx == 0 || !is_java_id_part(code.as_bytes()[idx - 1]);
        let after_idx = idx + name.len();
        let after_ok = after_idx >= code.len()
            || !is_java_id_part(code.as_bytes()[after_idx]);
        if before_ok && after_ok {
            return true;
        }
        start = idx + name.len().max(1);
    }
    false
}

/// True when `segment` appears as a dotted-name component (not a bare ident).
///
/// Matches plan language: artifact segments inside FQCNs such as
/// `org.junit.Test`, not local variables named like the artifactId.
fn qualified_segment_in_code(code: &str, segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    let mut start = 0usize;
    while let Some(pos) = code[start..].find(segment) {
        let idx = start + pos;
        let before = if idx == 0 {
            None
        } else {
            Some(code.as_bytes()[idx - 1])
        };
        let after_idx = idx + segment.len();
        let after = if after_idx >= code.len() {
            None
        } else {
            Some(code.as_bytes()[after_idx])
        };
        let before_ok = before.is_none_or(|b| !is_java_id_part(b));
        let after_ok = after.is_none_or(|b| !is_java_id_part(b));
        let dotted = before == Some(b'.') || after == Some(b'.');
        if before_ok && after_ok && dotted {
            return true;
        }
        start = idx + segment.len().max(1);
    }
    false
}

fn normalize_import_path(rest: &str) -> Option<String> {
    let mut path = rest.trim().trim_end_matches(';').trim().to_string();
    if path.is_empty() {
        return None;
    }
    if let Some(idx) = path.find(" as ") {
        path.truncate(idx);
        path = path.trim().to_string();
    }
    if let Some(stripped) = path.strip_suffix(".*") {
        path = stripped.trim().to_string();
    }
    if path.is_empty() { None } else { Some(path) }
}

fn extract_import_path(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("import static ")
        .or_else(|| trimmed.strip_prefix("import "))?;
    normalize_import_path(rest)
}

fn import_matches_package(import_path: &str, name: &str) -> bool {
    let Some((group, artifact)) = name.split_once(':') else {
        return false;
    };
    for prefix in group_import_prefixes(group) {
        if import_path == prefix
            || import_path.starts_with(&format!("{prefix}."))
        {
            return true;
        }
    }
    // Import paths are already qualified; artifact-as-segment is safe here.
    if !is_generic_artifact_id(artifact) {
        let segs: Vec<&str> = import_path.split('.').collect();
        if segs.contains(&artifact) {
            return true;
        }
    }
    false
}

fn code_references_package(code: &str, name: &str) -> bool {
    let Some((group, artifact)) = name.split_once(':') else {
        return false;
    };
    for prefix in group_import_prefixes(group) {
        if java_name_in_code(code, &prefix) {
            return true;
        }
    }
    if !is_generic_artifact_id(artifact)
        && qualified_segment_in_code(code, artifact)
    {
        return true;
    }
    false
}

fn package_decision_ambiguous(name: &str) -> bool {
    let Some((group, artifact)) = name.split_once(':') else {
        return true;
    };
    !group.contains('.') || is_generic_artifact_id(artifact)
}

fn scrubbed_code_lines(content: &str) -> Vec<String> {
    scrub_c_style_comments(content)
        .lines()
        .map(|line| {
            line_code_for_symbol_match(line, LineCommentStyle::SlashSlash)
        })
        .collect()
}

fn collect_source_index(context: &TierBContext<'_>) -> JavaSourceIndex {
    let excludes = merged_excludes(context);
    let files = list_java_kt_files(context, &excludes);
    let mut imports = HashSet::new();
    let mut scrubbed_files = Vec::new();
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
        let lines = scrubbed_code_lines(&content);
        for code in &lines {
            if let Some(import_path) = extract_import_path(code) {
                imports.insert(import_path);
            }
        }
        scrubbed_files.push((path, lines));
    }
    JavaSourceIndex {
        imports,
        scrubbed_files,
    }
}

fn cached_source_index(context: &TierBContext<'_>) -> JavaSourceIndex {
    let key = cache_key(context);
    if let Some(cached) = source_index_cache()
        .lock()
        .expect("java reachability cache lock poisoned")
        .get(&key)
        .cloned()
    {
        return cached;
    }
    let index = collect_source_index(context);
    source_index_cache()
        .lock()
        .expect("java reachability cache lock poisoned")
        .insert(key, index.clone());
    index
}

fn package_imported(imports: &HashSet<String>, name: &str) -> bool {
    imports.iter().any(|imp| import_matches_package(imp, name))
}

fn package_used_in_scrubbed(
    scrubbed_files: &[(PathBuf, Vec<String>)],
    name: &str,
) -> bool {
    for (_path, lines) in scrubbed_files {
        for code in lines {
            if code_references_package(code, name) {
                return true;
            }
        }
    }
    false
}

fn tier_b_decision_for(index: &JavaSourceIndex, name: &str) -> TierBDecision {
    if name.is_empty() {
        return TierBDecision::Unknown;
    }
    if index.scrubbed_files.is_empty() {
        return TierBDecision::Unknown;
    }
    if package_imported(&index.imports, name)
        || package_used_in_scrubbed(&index.scrubbed_files, name)
    {
        return TierBDecision::Reachable;
    }
    if package_decision_ambiguous(name) {
        TierBDecision::Unknown
    } else {
        TierBDecision::NotReachable
    }
}

/// True when an import path is evidence for this advisory symbol (not merely
/// the Maven package). Avoids attributing every symbol to a package import.
fn import_matches_symbol(import_path: &str, symbol: &str) -> bool {
    import_path == symbol
        || symbol.starts_with(&format!("{import_path}."))
        || java_name_in_code(import_path, symbol)
}

fn tier_c_result_for(
    index: &JavaSourceIndex,
    name: &str,
    advisory_symbols: &[String],
) -> TierCResult {
    if index.scrubbed_files.is_empty() {
        return TierCResult::unknown();
    }
    let mut evidence = Vec::new();
    let mut saw = false;
    for (path, lines) in &index.scrubbed_files {
        for (idx, code) in lines.iter().enumerate() {
            for sym in advisory_symbols {
                let symbol_in_code = qualified_symbol_in_code(code, sym)
                    || java_name_in_code(code, sym);
                let symbol_import = extract_import_path(code)
                    .is_some_and(|imp| import_matches_symbol(&imp, sym));
                if symbol_in_code || symbol_import {
                    saw = true;
                    push_reachability_evidence(
                        &mut evidence,
                        path.clone(),
                        (idx + 1) as u32,
                        sym,
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
    } else if package_decision_ambiguous(name) {
        TierCDecision::Unknown
    } else {
        TierCDecision::NotReachable
    };
    TierCResult { decision, evidence }
}

impl ReachabilityAnalyzer for JavaTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "java"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &[MAVEN_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let index = cached_source_index(context);
        tier_b_decision_for(&index, &context.package.name)
    }

    fn supports_tier_c(&self) -> bool {
        true
    }

    fn analyze_tier_c(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCResult {
        let index = cached_source_index(context);
        tier_c_result_for(&index, &context.package.name, advisory_symbols)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use vlz_db::Package;

    fn ctx<'a>(
        scan_root: &'a Path,
        package: &'a Package,
        manifests: &'a [PathBuf],
        exclude: &'a std::collections::HashSet<String>,
    ) -> TierBContext<'a> {
        TierBContext {
            scan_root,
            manifest_paths: manifests,
            package,
            exclude_dir_names: exclude,
            language: "java",
        }
    }

    #[test]
    fn generic_artifact_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("App.java");
        std::fs::write(&src, "import com.example.common.Util;\n").unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.other:common".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Unknown);
    }

    #[test]
    fn guava_import_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("App.java");
        std::fs::write(&src, "import com.google.common.collect.Lists;\n")
            .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.google.guava:guava".into(),
            version: "33.0.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn kotlin_import_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("App.kt");
        std::fs::write(src, "import org.junit.jupiter.api.Test\n").unwrap();
        let manifest = dir.path().join("build.gradle.kts");
        std::fs::write(&manifest, "plugins {}").unwrap();
        let pkg = Package {
            name: "org.junit.jupiter:junit-jupiter".into(),
            version: "5.10.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn empty_package_name_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = Package {
            name: String::new(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(Vec::<PathBuf>::new()));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Unknown);
    }

    #[test]
    fn static_import_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "import static com.example.Util.helper;\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example:Util".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn analyzer_metadata() {
        let analyzer = JavaTierBAnalyzer::new();
        assert_eq!(analyzer.language_name(), "java");
        assert!(analyzer.ecosystems().contains(&MAVEN_ECOSYSTEM));
        assert!(analyzer.supports_tier_c());
    }

    #[test]
    fn fqcn_without_import_is_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "class App {\n  void m() {\n    com.google.common.collect.Lists.newArrayList();\n  }\n}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.google.guava:guava".into(),
            version: "33.0.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn commented_import_is_not_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "// import com.example.widget.Widget;\nclass App {}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::NotReachable);
    }

    #[test]
    fn block_comment_import_is_not_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "/* import com.example.widget.Widget; */\nclass App {}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::NotReachable);
    }

    #[test]
    fn confident_absence_is_not_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("App.java"), "class App {}\n").unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::NotReachable);
    }

    #[test]
    fn short_group_without_dot_stays_unknown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("App.java"), "class App {}\n").unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "junit:junit".into(),
            version: "4.13.2".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Unknown);
    }

    #[test]
    fn kotlin_alias_import_is_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.kt"),
            "import org.junit.jupiter.api.Test as Spec\n",
        )
        .unwrap();
        let manifest = dir.path().join("build.gradle.kts");
        std::fs::write(&manifest, "plugins {}").unwrap();
        let pkg = Package {
            name: "org.junit.jupiter:junit-jupiter".into(),
            version: "5.10.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn star_import_is_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "import com.google.common.collect.*;\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.google.guava:guava".into(),
            version: "33.0.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn tier_c_emits_evidence_for_advisory_symbol() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "class App {\n  void m() {\n    com.example.Lib.vulnerable();\n  }\n}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example:lib".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        let result = analyzer
            .analyze_tier_c(&c, &["com.example.Lib.vulnerable".to_string()]);
        assert_eq!(result.decision, TierCDecision::Reachable);
        assert!(!result.evidence.is_empty());
        assert_eq!(result.evidence[0].symbol, "com.example.Lib.vulnerable");
    }

    #[test]
    fn tier_c_confident_miss_is_not_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("App.java"), "class App {}\n").unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        let result = analyzer
            .analyze_tier_c(&c, &["com.example.widget.Evil".to_string()]);
        assert_eq!(result.decision, TierCDecision::NotReachable);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn cache_key_includes_extra_java_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = Package {
            name: "com.example:lib".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let empty = Box::leak(Box::new(HashSet::new()));
        let manifests = Box::leak(Box::new(Vec::<PathBuf>::new()));
        let c = ctx(dir.path(), &pkg, manifests, empty);
        assert!(cache_key(&c).contains(".gradle"));
    }

    #[test]
    fn bare_artifact_identifier_is_not_enough_for_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "class App {\n  String widget = \"local\";\n}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::NotReachable);
    }

    #[test]
    fn artifact_segment_in_fqcn_is_reachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "class App {\n  void m() {\n    org.junit.Test t = null;\n  }\n}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "org.junit:junit".into(),
            version: "4.13.2".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn string_literal_block_marker_does_not_hide_import() {
        let dir = tempfile::tempdir().unwrap();
        // Import after a line-comment decoy that contains /* so naive
        // block strippers would swallow the real import; string "/*" must
        // also not open a block comment.
        std::fs::write(
            dir.path().join("App.java"),
            "class App {\n  String a = \"/*\";\n}\n// decoy /*\nimport com.example.widget.Widget;\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        assert_eq!(analyzer.analyze_tier_b(&c), TierBDecision::Reachable);
    }

    #[test]
    fn tier_c_package_import_alone_does_not_attribute_unrelated_symbol() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("App.java"),
            "import com.example.widget.Widget;\nclass App {}\n",
        )
        .unwrap();
        let manifest = dir.path().join("pom.xml");
        std::fs::write(&manifest, "<project/>").unwrap();
        let pkg = Package {
            name: "com.example.widget:widget".into(),
            version: "1.0".into(),
            ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
        };
        let exclude = Box::leak(Box::new(std::collections::HashSet::new()));
        let manifests = Box::leak(Box::new(vec![manifest.clone()]));
        let analyzer = JavaTierBAnalyzer::new();
        let c = ctx(dir.path(), &pkg, manifests, exclude);
        // Class import is evidence for that type symbol...
        let hit = analyzer
            .analyze_tier_c(&c, &["com.example.widget.Widget".to_string()]);
        assert_eq!(hit.decision, TierCDecision::Reachable);
        assert_eq!(hit.evidence.len(), 1);
        // ...but not for an unrelated method symbol on the same package.
        let miss = analyzer.analyze_tier_c(
            &c,
            &["com.example.widget.Other.vulnerable".to_string()],
        );
        assert_eq!(miss.decision, TierCDecision::NotReachable);
        assert!(miss.evidence.is_empty());
    }
}
