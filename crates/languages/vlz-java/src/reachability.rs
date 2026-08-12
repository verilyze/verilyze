// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use vlz_db::MAVEN_ECOSYSTEM;
use vlz_reachability_trait::{
    ReachabilityAnalyzer, TierBContext, TierBDecision, list_files_with_ext,
};

use crate::coordinate::is_generic_artifact_id;

const JAVA_KT_EXTS: &[&str] = &["java", "kt"];

#[derive(Debug, Default)]
pub struct JavaTierBAnalyzer;

impl JavaTierBAnalyzer {
    pub fn new() -> Self {
        Self
    }
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

fn list_java_kt_files(context: &TierBContext<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scoped_roots(context) {
        for ext in JAVA_KT_EXTS {
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

fn import_matches_package(import_line: &str, name: &str) -> bool {
    let trimmed = import_line.trim();
    if !(trimmed.starts_with("import ")
        || trimmed.starts_with("import static "))
    {
        return false;
    }
    let rest = trimmed
        .strip_prefix("import static ")
        .or_else(|| trimmed.strip_prefix("import "))
        .unwrap_or("")
        .trim()
        .trim_end_matches(';');
    let Some((group, artifact)) = name.split_once(':') else {
        return false;
    };
    for prefix in group_import_prefixes(group) {
        if rest == prefix || rest.starts_with(&format!("{prefix}.")) {
            return true;
        }
    }
    if !is_generic_artifact_id(artifact) {
        let segs: Vec<&str> = rest.split('.').collect();
        #[allow(clippy::manual_contains)]
        if segs.iter().any(|seg| *seg == artifact) {
            return true;
        }
    }
    false
}

impl ReachabilityAnalyzer for JavaTierBAnalyzer {
    fn language_name(&self) -> &'static str {
        "java"
    }

    fn ecosystems(&self) -> &'static [&'static str] {
        &[MAVEN_ECOSYSTEM]
    }

    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision {
        let name = &context.package.name;
        if name.is_empty() {
            return TierBDecision::Unknown;
        }
        let files = list_java_kt_files(context);
        if files.is_empty() {
            return TierBDecision::Unknown;
        }
        let mut any_match = false;
        for path in files {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in content.lines() {
                if import_matches_package(line, name) {
                    any_match = true;
                    break;
                }
            }
            if any_match {
                break;
            }
        }
        if any_match {
            TierBDecision::Reachable
        } else {
            TierBDecision::Unknown
        }
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
    }
}
