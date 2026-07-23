// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Canonical exit codes and end-of-scan precedence (FR-010).

/// Analysis completed; no CVEs meet threshold (or FP-only with default `fp_exit_code`).
pub const EXIT_SUCCESS: i32 = 0;
/// Unhandled panic or explicit internal-integrity failure (FR-033).
pub const EXIT_INTERNAL_ERROR: i32 = 1;
/// Misconfiguration / usage error (invalid CLI, unknown provider, bad config).
pub const EXIT_MISCONFIGURATION: i32 = 2;
/// Required package manager not on `PATH` (FR-024).
pub const EXIT_MISSING_PACKAGE_MANAGER: i32 = 3;
/// Blocking manifest parse or resolution failure (FR-022, FR-037).
pub const EXIT_RESOLUTION_FAILED: i32 = 4;
/// CVE provider fetch failed after retries (FR-010).
pub const EXIT_PROVIDER_FETCH_FAILED: i32 = 5;
/// `--offline` blocked a required CVE lookup (FR-031).
pub const EXIT_OFFLINE_CACHE_MISS: i32 = 6;
/// Default exit when CVEs meet score/count threshold (FR-014).
pub const DEFAULT_CVE_EXIT_CODE: u8 = 86;
/// Default exit when only false-positives remain (FR-016).
pub const DEFAULT_FP_EXIT_CODE: u8 = 0;

/// Terminal signals gathered before end-of-scan exit selection (FR-010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitSignals {
    pub manifest_blocking_count: usize,
    pub provider_fetch_failed: bool,
    pub offline_cache_miss: bool,
    pub cve_threshold_met: bool,
    pub cve_exit_code: i32,
    pub fp_only: bool,
    pub fp_exit_code: i32,
}

impl ExitSignals {
    /// Build signals for `run_scan` / `run_preload` after the report phase.
    #[allow(clippy::too_many_arguments)]
    pub fn for_scan_end(
        manifest_blocking_count: usize,
        provider_fetch_failed: bool,
        offline_cache_miss: bool,
        meeting_threshold: usize,
        min_count: usize,
        exit_code_on_cve: Option<u8>,
        had_any_cves_before_fp_filter: bool,
        real_cve_count_after_fp: usize,
        fp_exit_code: Option<u8>,
    ) -> Self {
        let threshold_met = cve_threshold_met(meeting_threshold, min_count);
        let cve_exit = if threshold_met {
            exit_code_on_cve.unwrap_or(DEFAULT_CVE_EXIT_CODE) as i32
        } else {
            EXIT_SUCCESS
        };
        Self {
            manifest_blocking_count,
            provider_fetch_failed,
            offline_cache_miss,
            cve_threshold_met: threshold_met,
            cve_exit_code: cve_exit,
            fp_only: had_any_cves_before_fp_filter
                && real_cve_count_after_fp == 0,
            fp_exit_code: fp_exit_code.unwrap_or(DEFAULT_FP_EXIT_CODE) as i32,
        }
    }

    /// Minimal signals when CVE lookup was skipped (e.g. preload fail-fast).
    pub fn resolution_only(manifest_blocking_count: usize) -> Self {
        Self {
            manifest_blocking_count,
            provider_fetch_failed: false,
            offline_cache_miss: false,
            cve_threshold_met: false,
            cve_exit_code: EXIT_SUCCESS,
            fp_only: false,
            fp_exit_code: DEFAULT_FP_EXIT_CODE as i32,
        }
    }
}

/// Exit-code precedence for scan completion (FR-010): 4 > 5 > 6 > 86 > fp > 0.
pub fn pick_exit_code(s: &ExitSignals) -> i32 {
    if s.manifest_blocking_count > 0 {
        return EXIT_RESOLUTION_FAILED;
    }
    if s.provider_fetch_failed {
        return EXIT_PROVIDER_FETCH_FAILED;
    }
    if s.offline_cache_miss {
        return EXIT_OFFLINE_CACHE_MISS;
    }
    if s.cve_threshold_met {
        return s.cve_exit_code;
    }
    if s.fp_only {
        return s.fp_exit_code;
    }
    EXIT_SUCCESS
}

/// True when CVE count meets `min_score` / `min_count` trigger (FR-014).
pub fn cve_threshold_met(meeting_threshold: usize, min_count: usize) -> bool {
    if min_count == 0 {
        meeting_threshold >= 1
    } else {
        meeting_threshold >= min_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(
        blocking: usize,
        provider: bool,
        offline: bool,
        cve_met: bool,
        cve_code: i32,
        fp_only: bool,
        fp_code: i32,
    ) -> ExitSignals {
        ExitSignals {
            manifest_blocking_count: blocking,
            provider_fetch_failed: provider,
            offline_cache_miss: offline,
            cve_threshold_met: cve_met,
            cve_exit_code: cve_code,
            fp_only,
            fp_exit_code: fp_code,
        }
    }

    #[test]
    fn pick_exit_code_precedence_blocking_over_all() {
        let s = signals(1, true, true, true, 86, true, 99);
        assert_eq!(pick_exit_code(&s), EXIT_RESOLUTION_FAILED);
    }

    #[test]
    fn pick_exit_code_precedence_provider_over_offline_and_cve() {
        let s = signals(0, true, true, true, 86, false, 0);
        assert_eq!(pick_exit_code(&s), EXIT_PROVIDER_FETCH_FAILED);
    }

    #[test]
    fn pick_exit_code_precedence_offline_over_cve() {
        let s = signals(0, false, true, true, 86, false, 0);
        assert_eq!(pick_exit_code(&s), EXIT_OFFLINE_CACHE_MISS);
    }

    #[test]
    fn pick_exit_code_cve_over_fp_only() {
        let s = signals(0, false, false, true, 86, true, 77);
        assert_eq!(pick_exit_code(&s), 86);
    }

    #[test]
    fn pick_exit_code_fp_only_over_success() {
        let s = signals(0, false, false, false, 0, true, 77);
        assert_eq!(pick_exit_code(&s), 77);
    }

    #[test]
    fn pick_exit_code_success() {
        let s = signals(0, false, false, false, 0, false, 0);
        assert_eq!(pick_exit_code(&s), EXIT_SUCCESS);
    }

    #[test]
    fn cve_threshold_met_min_count_zero_requires_one() {
        assert!(!cve_threshold_met(0, 0));
        assert!(cve_threshold_met(1, 0));
    }

    #[test]
    fn cve_threshold_met_min_count_positive() {
        assert!(!cve_threshold_met(1, 3));
        assert!(cve_threshold_met(3, 3));
    }

    #[test]
    fn for_scan_end_fp_only_when_all_filtered() {
        let s = ExitSignals::for_scan_end(
            0,
            false,
            false,
            0,
            0,
            None,
            true,
            0,
            Some(42),
        );
        assert!(s.fp_only);
        assert_eq!(pick_exit_code(&s), 42);
    }

    #[test]
    fn for_scan_end_offline_beats_fp_only() {
        let s = ExitSignals::for_scan_end(
            0,
            false,
            true,
            0,
            0,
            None,
            true,
            0,
            Some(42),
        );
        assert_eq!(pick_exit_code(&s), EXIT_OFFLINE_CACHE_MISS);
    }
}
