// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Explicit `vlz fix --format diff` recipe output (FR-041).
//!
//! Ambient stdout remains reserved for requested reports (NFR-013 / SEC-009).
//! Diff text is emitted only when the operator selects `--format diff`
//! (and optional `--output PATH`).

use std::path::{Path, PathBuf};
use vlz_db::Package;
use vlz_remediate::{RemediationPreview, UpgradePlan};

/// One planned remediation row used when rendering `--format diff`.
#[derive(Debug, Clone)]
pub struct FixDiffEntry<'a> {
    pub package: &'a Package,
    pub upgrade_plan: &'a UpgradePlan,
    pub preview: Option<&'a RemediationPreview>,
    pub sbom_only: bool,
}

/// Render a unified-diff style recipe for PR bots / `git apply` consumers.
///
/// Package-manager strategies cannot always produce real file content diffs
/// without executing the remediator; this format records intended files and
/// argv as a synthetic recipe file under `vlz-fix/` so selection is explicit.
pub fn format_fix_diff_recipe(
    entries: &[FixDiffEntry<'_>],
    scan_root: &Path,
) -> String {
    let mut out = String::new();
    if entries.is_empty() {
        out.push_str("No upgrade plan entries produced.\n");
        return out;
    }
    for entry in entries {
        let safe_name = sanitize_recipe_name(&entry.package.name);
        let recipe_path = format!("vlz-fix/{safe_name}.recipe");
        let body = recipe_body(entry, scan_root);
        let body_lines: Vec<&str> = body.lines().collect();
        let n = body_lines.len().max(1);
        out.push_str(&format!("diff --git a/{recipe_path} b/{recipe_path}\n"));
        out.push_str("new file mode 100644\n");
        out.push_str(&format!("--- /dev/null\n+++ b/{recipe_path}\n"));
        out.push_str(&format!("@@ -0,0 +1,{n} @@\n"));
        for line in &body_lines {
            out.push('+');
            out.push_str(line);
            out.push('\n');
        }
        if body_lines.is_empty() {
            out.push_str("+\n");
        }
    }
    out
}

fn sanitize_recipe_name(name: &str) -> String {
    let mut s = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            s.push(ch);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() { "package".into() } else { s }
}

fn rel_display(path: &Path, scan_root: &Path) -> String {
    path.strip_prefix(scan_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn recipe_body(entry: &FixDiffEntry<'_>, scan_root: &Path) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "# vlz fix recipe: {}@{} -> {} [{}]",
        entry.package.name,
        entry.package.version,
        entry.upgrade_plan.minimal_fixed_version,
        entry.upgrade_plan.apply_strategy.as_str()
    ));
    if entry.sbom_only {
        lines
            .push("# SBOM entry point: dry-run only; never apply".to_string());
    }
    if let Some(preview) = entry.preview {
        lines.push(format!(
            "# workdir: {}",
            rel_display(&preview.workdir, scan_root)
        ));
        let files: Vec<String> = preview
            .files
            .iter()
            .map(|p| rel_display(p, scan_root))
            .collect();
        lines.push(format!("# files: {}", files.join(", ")));
        if preview.argv.is_empty() {
            lines.push(
                "# argv: (file-edit strategy; no subprocess)".to_string(),
            );
        } else {
            lines.push(format!("# argv: {}", preview.argv.join(" ")));
        }
        lines.push(
            "# note: package-manager strategies need argv under workdir; \
             file-edit strategies rewrite listed files on apply"
                .to_string(),
        );
    } else {
        lines.push("# preview: unavailable".to_string());
    }
    lines.join("\n")
}

/// Build a relative path under scan root for tests / callers.
pub fn recipe_rel_path(package_name: &str) -> PathBuf {
    PathBuf::from("vlz-fix")
        .join(format!("{}.recipe", sanitize_recipe_name(package_name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_remediate::{
        ApplyStrategy, DependencyKind, UpgradePlanConfidence,
    };

    fn plan(strategy: ApplyStrategy) -> UpgradePlan {
        UpgradePlan {
            minimal_fixed_version: "2.0.0".into(),
            dependency_kind: DependencyKind::Direct,
            apply_strategy: strategy,
            confidence: UpgradePlanConfidence::High,
        }
    }

    #[test]
    fn empty_entries_message() {
        let text = format_fix_diff_recipe(&[], Path::new("/tmp"));
        assert!(text.contains("No upgrade plan"));
    }

    #[test]
    fn emits_unified_diff_recipe_for_preview() {
        let pkg = Package {
            name: "lodash".into(),
            version: "4.17.20".into(),
            ecosystem: Some("npm".into()),
        };
        let upgrade = plan(ApplyStrategy::Npm);
        let preview = RemediationPreview {
            strategy: ApplyStrategy::Npm,
            workdir: PathBuf::from("/tmp/app"),
            files: vec![PathBuf::from("/tmp/app/package-lock.json")],
            argv: vec![
                "npm".into(),
                "install".into(),
                "--ignore-scripts".into(),
                "--package-lock-only".into(),
                "--".into(),
                "lodash@4.17.21".into(),
            ],
        };
        let entry = FixDiffEntry {
            package: &pkg,
            upgrade_plan: &upgrade,
            preview: Some(&preview),
            sbom_only: false,
        };
        let text = format_fix_diff_recipe(&[entry], Path::new("/tmp/app"));
        assert!(text.contains("diff --git a/vlz-fix/lodash.recipe"));
        assert!(text.contains("new file mode"));
        assert!(text.contains("+# argv: npm install"));
        assert!(text.contains("package-lock.json"));
        assert!(!text.contains("ambient"));
    }

    #[test]
    fn sanitizes_package_names_in_path() {
        assert_eq!(
            recipe_rel_path("group:artifact").display().to_string(),
            "vlz-fix/group_artifact.recipe"
        );
    }
}
