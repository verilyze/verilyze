// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
#[cfg(feature = "perf-instrumentation")]
use std::sync::atomic::{AtomicU64, Ordering};

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

pub trait ReachabilityAnalyzer: Send + Sync {
    fn language_name(&self) -> &'static str;
    fn ecosystems(&self) -> &'static [&'static str];
    fn analyze_tier_b(&self, context: &TierBContext<'_>) -> TierBDecision;
}

#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILE_ENUM_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILES_ENUMERATED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILE_READ_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-instrumentation")]
static TIER_B_FILE_READ_SUCCESSES: AtomicU64 = AtomicU64::new(0);

pub fn reset_tier_b_counters() {
    #[cfg(feature = "perf-instrumentation")]
    {
        TIER_B_FILE_ENUM_CALLS.store(0, Ordering::Relaxed);
        TIER_B_FILES_ENUMERATED.store(0, Ordering::Relaxed);
        TIER_B_FILE_READ_ATTEMPTS.store(0, Ordering::Relaxed);
        TIER_B_FILE_READ_SUCCESSES.store(0, Ordering::Relaxed);
    }
}

pub fn snapshot_tier_b_counters() -> (u64, u64, u64, u64) {
    #[cfg(feature = "perf-instrumentation")]
    {
        (
            TIER_B_FILE_ENUM_CALLS.load(Ordering::Relaxed),
            TIER_B_FILES_ENUMERATED.load(Ordering::Relaxed),
            TIER_B_FILE_READ_ATTEMPTS.load(Ordering::Relaxed),
            TIER_B_FILE_READ_SUCCESSES.load(Ordering::Relaxed),
        )
    }
    #[cfg(not(feature = "perf-instrumentation"))]
    {
        (0, 0, 0, 0)
    }
}

#[cfg(feature = "perf-instrumentation")]
fn note_tier_b_file_enum_call() {
    TIER_B_FILE_ENUM_CALLS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "perf-instrumentation"))]
fn note_tier_b_file_enum_call() {}

#[cfg(feature = "perf-instrumentation")]
fn note_tier_b_files_enumerated(count: usize) {
    TIER_B_FILES_ENUMERATED.fetch_add(count as u64, Ordering::Relaxed);
}

#[cfg(not(feature = "perf-instrumentation"))]
fn note_tier_b_files_enumerated(_count: usize) {}

pub fn note_tier_b_file_read_attempt(success: bool) {
    let _ = success;
    #[cfg(feature = "perf-instrumentation")]
    {
        TIER_B_FILE_READ_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        if success {
            TIER_B_FILE_READ_SUCCESSES.fetch_add(1, Ordering::Relaxed);
        }
    }
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

    #[cfg(feature = "perf-instrumentation")]
    #[test]
    fn counters_record_when_feature_enabled() {
        reset_tier_b_counters();
        note_tier_b_file_enum_call();
        note_tier_b_files_enumerated(3);
        note_tier_b_file_read_attempt(true);
        let (enum_calls, files_enumerated, read_attempts, read_successes) =
            snapshot_tier_b_counters();
        assert_eq!(enum_calls, 1);
        assert_eq!(files_enumerated, 3);
        assert_eq!(read_attempts, 1);
        assert_eq!(read_successes, 1);
    }
}
