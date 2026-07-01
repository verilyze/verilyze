// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Multi-manifest scan orchestration helpers (FR-037, FR-010).

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

/// Exit-code precedence for scan completion (FR-010): 2 > 5 > 4 > cve_exit.
pub fn pick_exit_code(
    manifest_blocking_count: usize,
    offline_cache_miss: bool,
    provider_fetch_failed: bool,
    cve_exit: i32,
) -> i32 {
    if manifest_blocking_count > 0 {
        return 2;
    }
    if provider_fetch_failed {
        return 5;
    }
    if offline_cache_miss {
        return 4;
    }
    cve_exit
}

/// Count manifest coverage entries that are blocking failures (FR-037).
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
    for entry in failures {
        let path = relative_manifest_display(&entry.path, root_path);
        let reason = entry
            .error
            .as_deref()
            .unwrap_or_else(|| entry.status.as_str());
        out.push_str(&format!("\n  - {path}: {reason}"));
    }
    out.push('\n');
    out.push_str(MANIFEST_FAILURE_SUMMARY_FOOTER);
    Some(out)
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
    }
}

/// Log a manifest failure to stderr with optional cause chain (NFR-018).
pub fn log_manifest_failure(
    manifest_path: &Path,
    err: &(dyn std::error::Error + 'static),
    verbosity: u8,
) {
    eprintln!("Error: manifest {}: {}", manifest_path.display(), err);
    if verbosity > 0 {
        let mut source = err.source();
        while let Some(cause) = source {
            eprintln!("  Caused by: {}", cause);
            source = cause.source();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_manifest_parser::ResolverError;
    use vlz_report::{
        MANIFEST_STATUS_FAILED_PARSE, MANIFEST_STATUS_FAILED_RESOLUTION,
    };

    #[test]
    fn pick_exit_code_precedence_manifest_over_provider_and_cve() {
        assert_eq!(pick_exit_code(1, true, true, 86), 2);
        assert_eq!(pick_exit_code(0, true, true, 86), 5);
        assert_eq!(pick_exit_code(0, true, false, 86), 4);
        assert_eq!(pick_exit_code(0, false, false, 86), 86);
        assert_eq!(pick_exit_code(0, false, false, 0), 0);
    }

    #[test]
    fn format_manifest_failure_summary_empty_when_no_blocking() {
        let coverage = vec![ManifestCoverageEntry {
            path: PathBuf::from("ok/requirements.txt"),
            language: "python".to_string(),
            status: ManifestScanStatus::ScannedTransitive,
            direct_only_reason: None,
            error: None,
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
            },
            ManifestCoverageEntry {
                path: PathBuf::from("/root/good/requirements.txt"),
                language: "python".to_string(),
                status: ManifestScanStatus::ScannedTransitive,
                direct_only_reason: None,
                error: None,
            },
        ];
        let summary = format_manifest_failure_summary(
            &coverage,
            Some(Path::new("/root")),
        )
        .expect("summary");
        assert!(summary.contains("1 manifest(s) could not be fully analyzed"));
        assert!(summary.contains("broken/requirements.txt: resolve failed"));
        assert!(summary.contains(MANIFEST_FAILURE_SUMMARY_FOOTER));
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
