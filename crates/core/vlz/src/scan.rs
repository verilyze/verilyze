// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Multi-manifest scan orchestration helpers (FR-037, FR-010).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use vlz_manifest_parser::{
    ParserError, ResolutionDepth, ResolveResult, ResolverError,
};
use vlz_report::{ManifestCoverageEntry, ManifestScanStatus};

/// Outcome of parsing and resolving a single manifest (FR-037).
pub enum ManifestTaskOutcome {
    Success {
        resolved: ResolveResult,
        manifest_path: PathBuf,
        language: String,
    },
    ParseFailed {
        manifest_path: PathBuf,
        language: String,
        error: ParserError,
    },
    ResolveFailed {
        manifest_path: PathBuf,
        language: String,
        error: ResolverError,
    },
}

impl ManifestTaskOutcome {
    /// Stable sort key for post-`join_all` ordering.
    pub fn manifest_path(&self) -> &Path {
        match self {
            Self::Success { manifest_path, .. }
            | Self::ParseFailed { manifest_path, .. }
            | Self::ResolveFailed { manifest_path, .. } => manifest_path,
        }
    }
}

/// Header for consolidated manifest-failure summary (NFR-024). `{}` is the failure count.
pub const MANIFEST_FAILURE_SUMMARY_HEADER: &str =
    "vlz: {} manifest(s) could not be fully analyzed:";
/// Footer pointing users to verbose cause chains (NFR-024).
pub const MANIFEST_FAILURE_SUMMARY_FOOTER: &str =
    "Run with -v for full error detail on each manifest above.";

/// Header for consolidated direct-only summary (FR-022a). `{}` is the entry count.
pub const DIRECT_ONLY_SUMMARY_HEADER: &str =
    "vlz: {} manifest(s) scanned with direct dependencies only:";
/// Footer for direct-only summary remediation and verbose hint (FR-022a, NFR-024).
pub const DIRECT_ONLY_SUMMARY_FOOTER: &str = "Add an adjacent lock file for transitive coverage. See `man vlz` or docs/FAQ.md. Run with -v for per-manifest warning detail.";

/// Exit-code precedence for scan completion (FR-010): see [`crate::exit_code`].
pub fn count_blocking_manifest_failures(
    coverage: &[ManifestCoverageEntry],
) -> usize {
    coverage.iter().filter(|e| e.status.is_blocking()).count()
}

fn relative_manifest_display(path: &Path, root: Option<&Path>) -> String {
    if let Some(root) = root {
        path.strip_prefix(root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned())
    } else {
        path.to_string_lossy().into_owned()
    }
}

/// Consolidated stderr summary for blocking manifest failures (FR-022a, FR-037).
pub fn format_manifest_failure_summary(
    coverage: &[ManifestCoverageEntry],
    root_path: Option<&Path>,
) -> Option<String> {
    let failures: Vec<_> =
        coverage.iter().filter(|e| e.status.is_blocking()).collect();
    if failures.is_empty() {
        return None;
    }
    let mut out = MANIFEST_FAILURE_SUMMARY_HEADER
        .replace("{}", &failures.len().to_string());
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in failures {
        let path = relative_manifest_display(&entry.path, root_path);
        let reason = entry
            .error
            .as_deref()
            .unwrap_or_else(|| entry.status.as_str())
            .to_string();
        groups.entry(reason).or_default().push(path);
    }
    for (reason, paths) in groups {
        out.push_str(&format!("\n\n  {reason} ({}):", paths.len()));
        for path in paths {
            out.push_str(&format!("\n    - {path}"));
        }
    }
    out.push('\n');
    out.push_str(MANIFEST_FAILURE_SUMMARY_FOOTER);
    Some(out)
}

/// Consolidated stderr summary for direct-only coverage (FR-022a).
pub fn format_direct_only_summary(
    coverage: &[ManifestCoverageEntry],
    root_path: Option<&Path>,
) -> Option<String> {
    let entries: Vec<_> = coverage
        .iter()
        .filter(|e| e.status == ManifestScanStatus::ScannedDirectOnly)
        .collect();
    if entries.is_empty() {
        return None;
    }
    let mut out =
        DIRECT_ONLY_SUMMARY_HEADER.replace("{}", &entries.len().to_string());
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in entries {
        let path = relative_manifest_display(&entry.path, root_path);
        let reason = entry
            .direct_only_reason
            .as_deref()
            .unwrap_or_else(|| entry.status.as_str())
            .to_string();
        groups.entry(reason).or_default().push(path);
    }
    for (reason, paths) in groups {
        out.push_str(&format!("\n\n  {reason} ({}):", paths.len()));
        for path in paths {
            out.push_str(&format!("\n    - {path}"));
        }
    }
    out.push('\n');
    out.push_str(DIRECT_ONLY_SUMMARY_FOOTER);
    Some(out)
}

/// Collect `source()` chain strings for verbose stderr replay (NFR-018).
pub fn collect_error_causes(
    err: &(dyn std::error::Error + 'static),
) -> Vec<String> {
    let mut causes = Vec::new();
    let mut source = err.source();
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    causes
}

/// Emit end-of-scan manifest-failure diagnostics (FR-022a, FR-037).
///
/// Always prints the consolidated summary when non-empty. With `verbosity > 0`,
/// also prints per-manifest `Error: manifest` lines from coverage.
pub fn emit_manifest_failure_diagnostics(
    coverage: &[ManifestCoverageEntry],
    root_path: Option<&Path>,
    verbosity: u8,
) {
    if let Some(summary) = format_manifest_failure_summary(coverage, root_path)
    {
        crate::run::user_warning(&summary);
    }
    if verbosity == 0 {
        return;
    }
    for entry in coverage.iter().filter(|e| e.status.is_blocking()) {
        log_manifest_failure_from_coverage(entry, root_path);
    }
}

/// Emit end-of-scan direct-only diagnostics (FR-022a).
///
/// Always prints the consolidated summary when non-empty. With `verbosity > 0`,
/// also prints per-manifest `vlz warning:` lines from coverage.
pub fn emit_direct_only_diagnostics(
    coverage: &[ManifestCoverageEntry],
    root_path: Option<&Path>,
    verbosity: u8,
) {
    if let Some(summary) = format_direct_only_summary(coverage, root_path) {
        crate::run::user_warning(&summary);
    }
    if verbosity == 0 {
        return;
    }
    for entry in coverage
        .iter()
        .filter(|e| e.status == ManifestScanStatus::ScannedDirectOnly)
    {
        let Some(reason) = entry.direct_only_reason.as_deref() else {
            continue;
        };
        let path = relative_manifest_display(&entry.path, root_path);
        crate::run::user_warning(
            &vlz_manifest_parser::format_direct_only_warning(&path, reason),
        );
    }
}

/// Build a coverage entry for a successfully resolved manifest.
pub fn coverage_entry_success(
    manifest_path: PathBuf,
    language: String,
    resolved: &ResolveResult,
) -> ManifestCoverageEntry {
    let (status, direct_only_reason) =
        if resolved.depth == ResolutionDepth::Transitive {
            (ManifestScanStatus::ScannedTransitive, None)
        } else {
            (
                ManifestScanStatus::ScannedDirectOnly,
                resolved.direct_only_reason.map(|r| r.to_string()),
            )
        };
    ManifestCoverageEntry {
        path: manifest_path,
        language,
        status,
        direct_only_reason,
        error: None,
        error_causes: Vec::new(),
    }
}

/// Build a coverage entry and concise error string from a parser failure.
pub fn coverage_entry_parse_failure(
    manifest_path: PathBuf,
    language: String,
    err: &ParserError,
) -> ManifestCoverageEntry {
    ManifestCoverageEntry {
        path: manifest_path,
        language,
        status: ManifestScanStatus::FailedParse,
        direct_only_reason: None,
        error: Some(err.to_string()),
        error_causes: collect_error_causes(err),
    }
}

/// Build a coverage entry and concise error string from a resolver failure.
pub fn coverage_entry_resolution_failure(
    manifest_path: PathBuf,
    language: String,
    err: &ResolverError,
) -> ManifestCoverageEntry {
    ManifestCoverageEntry {
        path: manifest_path,
        language,
        status: ManifestScanStatus::FailedResolution,
        direct_only_reason: None,
        error: Some(err.to_string()),
        error_causes: collect_error_causes(err),
    }
}

/// Lines for verbose per-manifest failure stderr (NFR-018).
pub fn manifest_failure_detail_lines(
    entry: &ManifestCoverageEntry,
    root_path: Option<&Path>,
) -> Vec<String> {
    let path = relative_manifest_display(&entry.path, root_path);
    let message = entry
        .error
        .as_deref()
        .unwrap_or_else(|| entry.status.as_str());
    let mut lines = vec![format!("Error: manifest {path}: {message}")];
    for cause in &entry.error_causes {
        lines.push(format!("  Caused by: {cause}"));
    }
    lines
}

/// Log a blocking manifest failure from coverage (verbose end-of-scan detail).
pub fn log_manifest_failure_from_coverage(
    entry: &ManifestCoverageEntry,
    root_path: Option<&Path>,
) {
    for line in manifest_failure_detail_lines(entry, root_path) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_manifest_parser::{
        DIRECT_ONLY_REASON_OFFLINE, ParserError, ResolutionDepth,
        ResolveResult, ResolverError,
    };
    use vlz_report::{
        MANIFEST_STATUS_FAILED_PARSE, MANIFEST_STATUS_FAILED_RESOLUTION,
    };

    #[test]
    fn count_blocking_manifest_failures_mixed_statuses() {
        let coverage = vec![
            ManifestCoverageEntry {
                path: PathBuf::from("a.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedTransitive,
                direct_only_reason: None,
                error: None,
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("b.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedParse,
                direct_only_reason: None,
                error: Some("parse".to_string()),
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("c.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedResolution,
                direct_only_reason: None,
                error: Some("resolve".to_string()),
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("d.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedDirectOnly,
                direct_only_reason: Some("offline mode".to_string()),
                error: None,
                error_causes: Vec::new(),
            },
        ];
        assert_eq!(count_blocking_manifest_failures(&coverage), 2);
    }

    #[test]
    fn format_manifest_failure_summary_empty_when_no_blocking() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("ok/requirements.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::ScannedTransitive,
            direct_only_reason: None,
            error: None,
            error_causes: Vec::new(),
        }];
        assert!(format_manifest_failure_summary(&coverage, None).is_none());
    }

    #[test]
    fn format_manifest_failure_summary_lists_failures_with_count() {
        let coverage = vec![
            ManifestCoverageEntry {
                path: PathBuf::from("/root/broken/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedResolution,
                direct_only_reason: None,
                error: Some("resolve failed".to_string()),
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("/root/good/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedTransitive,
                direct_only_reason: None,
                error: None,
                error_causes: Vec::new(),
            },
        ];
        let summary = format_manifest_failure_summary(
            &coverage,
            Some(Path::new("/root")),
        )
        .expect("summary");
        assert!(summary.contains("1 manifest(s) could not be fully analyzed"));
        assert!(summary.contains("resolve failed (1):"));
        assert!(summary.contains("broken/requirements.txt"));
        assert!(summary.contains(MANIFEST_FAILURE_SUMMARY_FOOTER));
    }

    #[test]
    fn format_manifest_failure_summary_without_root_uses_full_path() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("/abs/broken/requirements.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::FailedParse,
            direct_only_reason: None,
            error: Some("bad syntax".to_string()),
            error_causes: Vec::new(),
        }];
        let summary =
            format_manifest_failure_summary(&coverage, None).expect("summary");
        assert!(summary.contains("/abs/broken/requirements.txt"));
        assert!(summary.contains("bad syntax (1):"));
    }

    #[test]
    fn format_manifest_failure_summary_strip_prefix_fallback() {
        let coverage = vec![
            ManifestCoverageEntry {
                path: PathBuf::from("/other/broken/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedParse,
                direct_only_reason: None,
                error: None,
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("/root/also/broken.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedResolution,
                direct_only_reason: None,
                error: Some("resolve".to_string()),
                error_causes: Vec::new(),
            },
        ];
        let summary = format_manifest_failure_summary(
            &coverage,
            Some(Path::new("/root")),
        )
        .expect("summary");
        assert!(summary.contains("2 manifest(s) could not be fully analyzed"));
        // Path outside root: full path and status.as_str() when error is None.
        assert!(summary.contains("/other/broken/requirements.txt"));
        assert!(summary.contains("failed_parse (1):"));
        assert!(summary.contains("also/broken.txt"));
        assert!(summary.contains("resolve (1):"));
    }

    #[test]
    fn format_manifest_failure_summary_groups_identical_errors() {
        let coverage = vec![
            ManifestCoverageEntry {
                path: PathBuf::from("/root/a/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedResolution,
                direct_only_reason: None,
                error: Some("same error".to_string()),
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("/root/b/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::FailedResolution,
                direct_only_reason: None,
                error: Some("same error".to_string()),
                error_causes: Vec::new(),
            },
        ];
        let summary = format_manifest_failure_summary(
            &coverage,
            Some(Path::new("/root")),
        )
        .expect("summary");
        assert!(summary.contains("same error (2):"));
        assert!(summary.contains("a/requirements.txt"));
        assert!(summary.contains("b/requirements.txt"));
        assert_eq!(summary.matches("same error (2):").count(), 1);
    }

    #[test]
    fn format_direct_only_summary_empty_when_none() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("ok/requirements.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::ScannedTransitive,
            direct_only_reason: None,
            error: None,
            error_causes: Vec::new(),
        }];
        assert!(format_direct_only_summary(&coverage, None).is_none());
    }

    #[test]
    fn format_direct_only_summary_lists_entries_grouped_by_reason() {
        let coverage = vec![
            ManifestCoverageEntry {
                path: PathBuf::from("/root/a/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedDirectOnly,
                direct_only_reason: Some(
                    DIRECT_ONLY_REASON_OFFLINE.to_string(),
                ),
                error: None,
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("/root/b/pyproject.toml"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedDirectOnly,
                direct_only_reason: Some(
                    DIRECT_ONLY_REASON_OFFLINE.to_string(),
                ),
                error: None,
                error_causes: Vec::new(),
            },
            ManifestCoverageEntry {
                path: PathBuf::from("/root/c/Cargo.toml"),
                language: "rust".to_string(),
                status: ManifestScanStatus::ScannedTransitive,
                direct_only_reason: None,
                error: None,
                error_causes: Vec::new(),
            },
        ];
        let summary =
            format_direct_only_summary(&coverage, Some(Path::new("/root")))
                .expect("summary");
        assert!(
            summary.contains(
                "2 manifest(s) scanned with direct dependencies only"
            )
        );
        assert!(summary.contains("offline mode (2):"));
        assert!(summary.contains("a/requirements.txt"));
        assert!(summary.contains("b/pyproject.toml"));
        assert!(!summary.contains("c/Cargo.toml"));
        assert!(summary.contains(DIRECT_ONLY_SUMMARY_FOOTER));
    }

    #[test]
    fn format_direct_only_summary_without_reason_uses_status() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("/root/req.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::ScannedDirectOnly,
            direct_only_reason: None,
            error: None,
            error_causes: Vec::new(),
        }];
        let summary =
            format_direct_only_summary(&coverage, Some(Path::new("/root")))
                .expect("summary");
        assert!(summary.contains("scanned_direct_only (1):"));
        assert!(summary.contains("req.txt"));
    }

    #[test]
    fn coverage_entry_success_transitive() {
        let resolved = ResolveResult {
            depth: ResolutionDepth::Transitive,
            ..Default::default()
        };
        let entry = coverage_entry_success(
            PathBuf::from("req.txt"),
            "python".to_string(),
            &resolved,
        );
        assert_eq!(entry.status, ManifestScanStatus::ScannedTransitive);
        assert!(entry.direct_only_reason.is_none());
        assert!(entry.error.is_none());
    }

    #[test]
    fn coverage_entry_success_direct_only_with_reason() {
        let resolved = ResolveResult {
            depth: ResolutionDepth::DirectOnly,
            direct_only_reason: Some(DIRECT_ONLY_REASON_OFFLINE),
            ..Default::default()
        };
        let entry = coverage_entry_success(
            PathBuf::from("req.txt"),
            "python".to_string(),
            &resolved,
        );
        assert_eq!(entry.status, ManifestScanStatus::ScannedDirectOnly);
        assert_eq!(
            entry.direct_only_reason.as_deref(),
            Some(DIRECT_ONLY_REASON_OFFLINE)
        );
    }

    #[test]
    fn coverage_entry_parse_failure_includes_error_string() {
        let err = ParserError::Parse("invalid line".to_string());
        let entry = coverage_entry_parse_failure(
            PathBuf::from("req.txt"),
            "python".to_string(),
            &err,
        );
        assert_eq!(entry.status, ManifestScanStatus::FailedParse);
        assert!(entry.error.unwrap().contains("invalid line"));
        assert!(entry.direct_only_reason.is_none());
    }

    #[test]
    fn manifest_task_outcome_manifest_path_all_variants() {
        let path = PathBuf::from("/proj/requirements.txt");
        let success = ManifestTaskOutcome::Success {
            resolved: ResolveResult::default(),
            manifest_path: path.clone(),
            language: "python".to_string(),
        };
        assert_eq!(success.manifest_path(), path.as_path());

        let parse_failed = ManifestTaskOutcome::ParseFailed {
            manifest_path: path.clone(),
            language: "python".to_string(),
            error: ParserError::Parse("x".to_string()),
        };
        assert_eq!(parse_failed.manifest_path(), path.as_path());

        let resolve_failed = ManifestTaskOutcome::ResolveFailed {
            manifest_path: path.clone(),
            language: "python".to_string(),
            error: ResolverError::Resolve("y".to_string()),
        };
        assert_eq!(resolve_failed.manifest_path(), path.as_path());
    }

    #[test]
    fn manifest_failure_detail_lines_includes_cause_chain() {
        let entry = coverage_entry_resolution_failure(
            PathBuf::from("req.txt"),
            "python".to_string(),
            &ResolverError::ResolveWithCause {
                message: "outer".to_string(),
                cause: Box::new(ResolverError::Resolve("inner".to_string())),
            },
        );
        let lines = manifest_failure_detail_lines(&entry, None);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Error: manifest req.txt:"));
        assert!(lines[0].contains("outer"));
        assert_eq!(lines[1], "  Caused by: Resolve error: inner");
    }

    #[test]
    fn manifest_failure_detail_lines_omits_causes_when_empty() {
        let entry = ManifestCoverageEntry {
            path: PathBuf::from("req.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::FailedParse,
            direct_only_reason: None,
            error: Some("Parse error: bad".to_string()),
            error_causes: Vec::new(),
        };
        let lines = manifest_failure_detail_lines(&entry, None);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("Parse error: bad"));
    }

    #[test]
    fn emit_manifest_failure_diagnostics_verbose_uses_detail_lines() {
        let entry = coverage_entry_resolution_failure(
            PathBuf::from("broken/req.txt"),
            "python".to_string(),
            &ResolverError::ResolveWithCause {
                message: "outer".to_string(),
                cause: Box::new(ResolverError::Resolve("inner".to_string())),
            },
        );
        let coverage = vec![entry];
        let detail = manifest_failure_detail_lines(
            &coverage[0],
            Some(Path::new("/root")),
        );
        assert!(
            detail.iter().any(|line| line.contains("Caused by:")),
            "verbose detail must include cause chain: {detail:?}"
        );
        // Smoke: emit path must not panic (stderr not captured here).
        emit_manifest_failure_diagnostics(
            &coverage,
            Some(Path::new("/root")),
            1,
        );
    }

    #[test]
    fn manifest_scan_status_constants_match_as_str() {
        assert_eq!(
            ManifestScanStatus::FailedParse.as_str(),
            MANIFEST_STATUS_FAILED_PARSE
        );
        assert_eq!(
            ManifestScanStatus::FailedResolution.as_str(),
            MANIFEST_STATUS_FAILED_RESOLUTION
        );
    }

    #[test]
    fn collect_error_causes_walks_source_chain() {
        let err = ResolverError::ResolveWithCause {
            message: "outer".to_string(),
            cause: Box::new(ResolverError::Resolve("inner".to_string())),
        };
        let causes = collect_error_causes(&err);
        assert_eq!(causes.len(), 1);
        assert!(causes[0].contains("inner"));
    }

    #[test]
    fn coverage_entry_resolution_failure_stores_error_causes() {
        let err = ResolverError::ResolveWithCause {
            message: "outer".to_string(),
            cause: Box::new(ResolverError::Resolve("inner".to_string())),
        };
        let entry = coverage_entry_resolution_failure(
            PathBuf::from("req.txt"),
            "python".to_string(),
            &err,
        );
        assert_eq!(entry.error_causes.len(), 1);
        assert!(entry.error_causes[0].contains("inner"));
    }

    #[test]
    fn coverage_entry_resolution_failure_from_resolve_with_cause() {
        let err = ResolverError::ResolveWithCause {
            message: "outer".to_string(),
            cause: Box::new(ResolverError::Resolve("inner".to_string())),
        };
        let entry = coverage_entry_resolution_failure(
            PathBuf::from("req.txt"),
            "python".to_string(),
            &err,
        );
        assert_eq!(entry.status, ManifestScanStatus::FailedResolution);
        assert!(entry.error.unwrap().contains("outer"));
    }
}
