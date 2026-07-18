// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod evidence_match;

pub use evidence_match::{
    LineCommentStyle, MAX_ADVISORY_SYMBOL_LEN, MAX_ADVISORY_SYMBOLS,
    cap_reachability_evidence, line_code_for_symbol_match,
    qualified_symbol_in_code, reachability_evidence_at_cap,
    sanitize_advisory_symbols,
};

#[cfg(feature = "perf-instrumentation")]
use std::cell::Cell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
#[cfg(feature = "perf-instrumentation")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "perf-instrumentation")]
use std::sync::{Mutex, MutexGuard, OnceLock};

use vlz_db::Package;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierBDecision {
    Reachable,
    NotReachable,
    Unknown,
}

impl TierBDecision {
    pub fn as_option_bool(self) -> Option<bool> {
        match self {
            TierBDecision::Reachable => Some(true),
            TierBDecision::NotReachable => Some(false),
            TierBDecision::Unknown => None,
        }
    }
}

pub struct TierBContext<'a> {
    pub scan_root: &'a Path,
    pub exclude_dir_names: &'a HashSet<String>,
    pub package: &'a Package,
    pub language: &'a str,
    pub manifest_paths: &'a [PathBuf],
}

/// Per-CVE reachability decision (Tier C); same semantics as [`TierBDecision`].
pub type TierCDecision = TierBDecision;

/// Maximum first-party evidence locations emitted per CVE (FR-032 symbol avoidance).
pub const MAX_REACHABILITY_EVIDENCE_PER_CVE: usize = 10;

/// JSON label when advisory symbols appear in first-party source.
pub const SYMBOL_USAGE_USED: &str = "used";
/// JSON label when advisory symbols are absent from first-party source (confident).
pub const SYMBOL_USAGE_NOT_FOUND: &str = "not_found";
/// JSON label when symbol usage in first-party source could not be determined.
pub const SYMBOL_USAGE_UNKNOWN: &str = "unknown";

/// First-party source location referencing an advisory symbol (provider-gated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityEvidence {
    pub path: PathBuf,
    pub start_line: u32,
    pub end_line: Option<u32>,
    pub symbol: String,
}

/// Tier C/D analysis outcome: reachability decision plus optional first-party evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierCResult {
    pub decision: TierCDecision,
    pub evidence: Vec<ReachabilityEvidence>,
}

impl TierCResult {
    pub fn unknown() -> Self {
        Self {
            decision: TierCDecision::Unknown,
            evidence: Vec::new(),
        }
    }

    pub fn from_decision(decision: TierCDecision) -> Self {
        Self {
            decision,
            evidence: Vec::new(),
        }
    }
}

/// Record a first-party evidence site when under the per-CVE cap (deduplicated).
/// Returns `false` when the cap is already reached (callers may stop scanning).
pub fn push_reachability_evidence(
    out: &mut Vec<ReachabilityEvidence>,
    path: PathBuf,
    start_line: u32,
    symbol: impl Into<String>,
) -> bool {
    if reachability_evidence_at_cap(out) {
        return false;
    }
    let symbol = symbol.into();
    if out.iter().any(|e| {
        e.path == path && e.start_line == start_line && e.symbol == symbol
    }) {
        return true;
    }
    out.push(ReachabilityEvidence {
        path,
        start_line,
        end_line: None,
        symbol,
    });
    true
}

/// Merge Tier C results from multiple language analyzers (FR-032).
pub fn merge_tier_c_results(
    results: impl IntoIterator<Item = TierCResult>,
) -> TierCResult {
    let mut merged = TierCResult::unknown();
    let mut saw_not_reachable = false;
    let mut saw_unknown = false;
    for result in results {
        merged.evidence.extend(result.evidence);
        match result.decision {
            TierCDecision::Reachable => {
                merged.decision = TierCDecision::Reachable
            }
            TierCDecision::NotReachable => saw_not_reachable = true,
            TierCDecision::Unknown => saw_unknown = true,
        }
    }
    if merged.decision != TierCDecision::Reachable {
        if saw_unknown {
            merged.decision = TierCDecision::Unknown;
        } else if saw_not_reachable {
            merged.decision = TierCDecision::NotReachable;
        }
    }
    cap_reachability_evidence(&mut merged.evidence);
    merged
}

pub trait ReachabilityAnalyzer: Send + Sync {
    fn language_name(&self) -> &'static str;
    fn ecosystems(&self) -> &'static [&'static str];
    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision;

    /// True when this analyzer can match advisory symbols (Tier C, FR-032 phase 2a).
    fn supports_tier_c(&self) -> bool {
        false
    }

    /// Match OSV `ecosystem_specific` symbols against consumer import evidence.
    fn analyze_tier_c(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCResult {
        let _ = (context, advisory_symbols);
        TierCResult::unknown()
    }

    /// True when this analyzer can refine Tier C unknowns with deeper source inspection.
    fn supports_tier_d(&self) -> bool {
        false
    }

    /// Refine reachability for Tier C unknowns using consumer source inspection (Tier D).
    fn analyze_tier_d(
        &self,
        context: &TierBContext<'_>,
        advisory_symbols: &[String],
    ) -> TierCResult {
        let _ = (context, advisory_symbols);
        TierCResult::unknown()
    }
}

#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILE_ENUM_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILES_ENUMERATED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILE_READ_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILE_READ_SUCCESSES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_COUNTER_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(feature = "perf-instrumentation")]
thread_local! {
    static TIER_B_COUNTERS_LOCKED: Cell<bool> = const { Cell::new(false) };
}

#[cfg(feature = "perf-instrumentation")]
struct TierBCounterGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

#[cfg(feature = "perf-instrumentation")]
impl Drop for TierBCounterGuard<'_> {
    fn drop(&mut self) {
        TIER_B_COUNTERS_LOCKED.set(false);
    }
}

#[cfg(feature = "perf-instrumentation")]
fn tier_b_counter_mutex() -> &'static Mutex<()> {
    TIER_B_COUNTER_MUTEX.get_or_init(|| Mutex::new(()))
}

#[cfg(feature = "perf-instrumentation")]
fn with_tier_b_counter_lock<R>(f: impl FnOnce() -> R) -> R {
    if TIER_B_COUNTERS_LOCKED.get() {
        return f();
    }
    let guard = tier_b_counter_mutex()
        .lock()
        .expect("tier B counter mutex poisoned");
    TIER_B_COUNTERS_LOCKED.set(true);
    let _guard = TierBCounterGuard { _guard: guard };
    f()
}

#[cfg(feature = "perf-instrumentation")]
fn reset_tier_b_counters_unlocked() {
    TIER_B_FILE_ENUM_CALLS.store(0, Ordering::Relaxed);
    TIER_B_FILES_ENUMERATED.store(0, Ordering::Relaxed);
    TIER_B_FILE_READ_ATTEMPTS.store(0, Ordering::Relaxed);
    TIER_B_FILE_READ_SUCCESSES.store(0, Ordering::Relaxed);
}

#[cfg(feature = "perf-instrumentation")]
fn snapshot_tier_b_counters_unlocked() -> (u64, u64, u64, u64) {
    (
        TIER_B_FILE_ENUM_CALLS.load(Ordering::Relaxed),
        TIER_B_FILES_ENUMERATED.load(Ordering::Relaxed),
        TIER_B_FILE_READ_ATTEMPTS.load(Ordering::Relaxed),
        TIER_B_FILE_READ_SUCCESSES.load(Ordering::Relaxed),
    )
}

pub fn reset_tier_b_counters() {
    #[cfg(feature = "perf-instrumentation")]
    with_tier_b_counter_lock(reset_tier_b_counters_unlocked);
}

pub fn snapshot_tier_b_counters() -> (u64, u64, u64, u64) {
    #[cfg(feature = "perf-instrumentation")]
    {
        with_tier_b_counter_lock(snapshot_tier_b_counters_unlocked)
    }
    #[cfg(not(feature = "perf-instrumentation"))]
    {
        (0, 0, 0, 0)
    }
}

/// Reset Tier B counters, run `f`, and return its result with a counter snapshot.
///
/// Holds the counter mutex for the whole call so parallel tests cannot pollute
/// measurements (nightly `coverage-extended` runs workspace tests in parallel).
pub fn measure_tier_b_counters<F, R>(f: F) -> (R, (u64, u64, u64, u64))
where
    F: FnOnce() -> R,
{
    #[cfg(feature = "perf-instrumentation")]
    {
        with_tier_b_counter_lock(|| {
            reset_tier_b_counters_unlocked();
            let result = f();
            let snapshot = snapshot_tier_b_counters_unlocked();
            (result, snapshot)
        })
    }
    #[cfg(not(feature = "perf-instrumentation"))]
    {
        (f(), (0, 0, 0, 0))
    }
}

#[cfg(feature = "perf-instrumentation")]
fn note_tier_b_file_enum_call() {
    with_tier_b_counter_lock(|| {
        TIER_B_FILE_ENUM_CALLS.fetch_add(1, Ordering::Relaxed);
    });
}

#[cfg(not(feature = "perf-instrumentation"))]
fn note_tier_b_file_enum_call() {}

#[cfg(feature = "perf-instrumentation")]
fn note_tier_b_files_enumerated(count: usize) {
    with_tier_b_counter_lock(|| {
        TIER_B_FILES_ENUMERATED.fetch_add(count as u64, Ordering::Relaxed);
    });
}

#[cfg(not(feature = "perf-instrumentation"))]
fn note_tier_b_files_enumerated(_count: usize) {}

pub fn note_tier_b_file_read_attempt(success: bool) {
    let _ = success;
    #[cfg(feature = "perf-instrumentation")]
    with_tier_b_counter_lock(|| {
        TIER_B_FILE_READ_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        if success {
            TIER_B_FILE_READ_SUCCESSES.fetch_add(1, Ordering::Relaxed);
        }
    });
}

pub fn list_files_with_ext(
    root: &Path,
    exclude_dir_names: &HashSet<String>,
    ext: &str,
) -> std::io::Result<Vec<PathBuf>> {
    note_tier_b_file_enum_call();
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in read.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if !should_skip_dir(&path, exclude_dir_names) {
                    stack.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == ext)
            {
                out.push(path);
            }
        }
    }
    note_tier_b_files_enumerated(out.len());
    Ok(out)
}

pub fn should_skip_dir(path: &Path, exclude: &HashSet<String>) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| exclude.contains(name))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "perf-instrumentation"))]
    #[test]
    fn counters_are_noop_when_feature_disabled() {
        reset_tier_b_counters();
        note_tier_b_file_read_attempt(true);
        assert_eq!(snapshot_tier_b_counters(), (0, 0, 0, 0));
    }

    #[test]
    fn tier_b_decision_as_option_bool() {
        assert_eq!(TierBDecision::Reachable.as_option_bool(), Some(true));
        assert_eq!(TierBDecision::NotReachable.as_option_bool(), Some(false));
        assert_eq!(TierBDecision::Unknown.as_option_bool(), None);
    }

    #[test]
    fn should_skip_dir_matches_exclude_set() {
        let mut exclude = HashSet::new();
        exclude.insert(".git".to_string());
        assert!(should_skip_dir(Path::new("/proj/.git"), &exclude));
        assert!(!should_skip_dir(Path::new("/proj/src"), &exclude));
        assert!(!should_skip_dir(Path::new("/"), &exclude));
    }

    struct DefaultsOnlyAnalyzer;

    impl ReachabilityAnalyzer for DefaultsOnlyAnalyzer {
        fn language_name(&self) -> &'static str {
            "test"
        }

        fn ecosystems(&self) -> &'static [&'static str] {
            &["PyPI"]
        }

        fn analyze_tier_b(&self, _: &TierBContext<'_>) -> TierBDecision {
            TierBDecision::Unknown
        }
    }

    #[test]
    fn default_tier_c_and_tier_d_trait_methods() {
        let analyzer = DefaultsOnlyAnalyzer;
        assert!(!analyzer.supports_tier_c());
        assert!(!analyzer.supports_tier_d());
        let pkg = Package {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
            ecosystem: Some("PyPI".to_string()),
        };
        let exclude = HashSet::new();
        let ctx = TierBContext {
            scan_root: Path::new("."),
            exclude_dir_names: &exclude,
            package: &pkg,
            language: "python",
            manifest_paths: &[],
        };
        assert_eq!(
            analyzer.analyze_tier_c(&ctx, &["sym".to_string()]).decision,
            TierCDecision::Unknown
        );
        assert_eq!(
            analyzer.analyze_tier_d(&ctx, &["sym".to_string()]).decision,
            TierCDecision::Unknown
        );
        assert!(
            analyzer
                .analyze_tier_c(&ctx, &["sym".to_string()])
                .evidence
                .is_empty()
        );
    }

    #[test]
    fn list_files_with_ext_finds_matching_and_skips_excluded_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("main.py"), "import x").expect("write");
        let excluded = dir.path().join("node_modules");
        std::fs::create_dir(&excluded).expect("mkdir");
        std::fs::write(excluded.join("skip.py"), "x").expect("write");
        let mut exclude = HashSet::new();
        exclude.insert("node_modules".to_string());
        let files =
            list_files_with_ext(dir.path(), &exclude, "py").expect("list");
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("main.py"));
    }

    #[test]
    fn list_files_with_ext_missing_root_returns_empty() {
        let exclude = HashSet::new();
        let files = list_files_with_ext(
            Path::new("/nonexistent/vlz-reachability-trait-root"),
            &exclude,
            "py",
        )
        .expect("list");
        assert!(files.is_empty());
    }

    #[test]
    fn list_files_with_ext_skips_non_matching_extension() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("readme.txt"), "x").expect("write");
        let exclude = HashSet::new();
        let files =
            list_files_with_ext(dir.path(), &exclude, "py").expect("list");
        assert!(files.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn list_files_with_ext_skips_unreadable_subdir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("ok.py"), "x").expect("write");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        std::fs::write(locked.join("hidden.py"), "x").expect("write");
        std::fs::set_permissions(
            &locked,
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("chmod");
        let exclude = HashSet::new();
        let files =
            list_files_with_ext(dir.path(), &exclude, "py").expect("list");
        // Restore perms so tempdir cleanup succeeds.
        let _ = std::fs::set_permissions(
            &locked,
            std::fs::Permissions::from_mode(0o755),
        );
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("ok.py"));
    }

    #[cfg(unix)]
    #[test]
    fn list_files_with_ext_skips_symlink_non_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("real.py"), "x").expect("write");
        let target = dir.path().join("target_dir");
        std::fs::create_dir(&target).expect("mkdir");
        std::os::unix::fs::symlink(&target, dir.path().join("link.py"))
            .expect("symlink");
        let exclude = HashSet::new();
        let files =
            list_files_with_ext(dir.path(), &exclude, "py").expect("list");
        // Symlink to a directory is not is_file(); only real.py should match.
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("real.py"));
    }

    #[cfg(feature = "perf-instrumentation")]
    #[test]
    fn counters_record_when_feature_enabled() {
        let (_, (enum_calls, files_enumerated, read_attempts, read_successes)) =
            measure_tier_b_counters(|| {
                note_tier_b_file_enum_call();
                note_tier_b_files_enumerated(3);
                note_tier_b_file_read_attempt(true);
            });
        assert_eq!(enum_calls, 1);
        assert_eq!(files_enumerated, 3);
        assert_eq!(read_attempts, 1);
        assert_eq!(read_successes, 1);
    }

    #[cfg(feature = "perf-instrumentation")]
    #[test]
    fn note_tier_b_file_read_attempt_false_does_not_increment_success() {
        let (_, (_, _, read_attempts, read_successes)) =
            measure_tier_b_counters(|| {
                note_tier_b_file_read_attempt(false);
            });
        assert_eq!(read_attempts, 1);
        assert_eq!(read_successes, 0);
    }

    #[cfg(feature = "perf-instrumentation")]
    #[test]
    fn reset_tier_b_counters_clears_snapshot() {
        let (_, snapshot) = measure_tier_b_counters(|| {
            note_tier_b_file_enum_call();
            note_tier_b_files_enumerated(2);
            note_tier_b_file_read_attempt(true);
        });
        assert_ne!(snapshot, (0, 0, 0, 0));
        reset_tier_b_counters();
        assert_eq!(snapshot_tier_b_counters(), (0, 0, 0, 0));
    }

    #[cfg(feature = "perf-instrumentation")]
    #[test]
    fn measure_tier_b_counters_excludes_concurrent_increments() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();
            note_tier_b_file_read_attempt(true);
        });

        let (_, (_, _, read_attempts, read_successes)) =
            measure_tier_b_counters(|| {
                barrier.wait();
                note_tier_b_file_read_attempt(true);
                thread::sleep(std::time::Duration::from_millis(50));
            });

        handle.join().expect("join");
        assert_eq!(read_attempts, 1);
        assert_eq!(read_successes, 1);
    }
}
