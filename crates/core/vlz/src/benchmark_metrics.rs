// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Benchmark mode metrics (FR-029, NFR-001).

use std::time::Instant;

/// CPU utilization is not sampled cross-platform yet; reserved for future use.
pub const BENCHMARK_CPU_PERCENT_NOT_SAMPLED: u32 = 0;

/// NFR-001: maximum `--benchmark` scan duration on reference CI hardware (ms).
pub const BENCHMARK_MAX_MS: u64 = 30_000;

/// Collected at end of a `--benchmark` scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkMetrics {
    pub duration_ms: u64,
    pub cpu_percent: u32,
    pub mem_mb: u64,
}

impl BenchmarkMetrics {
    /// Build metrics from a scan start instant (FR-029).
    pub fn from_start(start: Instant) -> Self {
        Self {
            duration_ms: start.elapsed().as_millis() as u64,
            cpu_percent: BENCHMARK_CPU_PERCENT_NOT_SAMPLED,
            mem_mb: current_rss_mb(),
        }
    }

    /// Single-line JSON object written to stdout after benchmark scans.
    pub fn to_json_line(self) -> String {
        format!(
            r#"{{"benchmark":{{"duration_ms":{},"cpu_percent":{},"mem_mb":{}}}}}"#,
            self.duration_ms, self.cpu_percent, self.mem_mb
        )
    }
}

/// Resident set size in megabytes (best-effort; 0 when unavailable).
pub fn current_rss_mb() -> u64 {
    current_rss_kb().map(|kb| kb / 1024).unwrap_or(0)
}

fn current_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        return read_linux_rss_kb();
    }
    #[cfg(target_os = "macos")]
    {
        return read_macos_rss_kb();
    }
    #[cfg(target_os = "windows")]
    {
        return read_windows_rss_kb();
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(target_os = "linux")]
fn read_linux_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(kb) = line.strip_prefix("VmRSS:") {
            let kb_str = kb.trim().strip_suffix(" kB")?.trim();
            return kb_str.parse().ok();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_macos_rss_kb() -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    text.trim().parse().ok()
}

#[cfg(target_os = "windows")]
fn read_windows_rss_kb() -> Option<u64> {
    // ps is not guaranteed on Windows CI; RSS sampling deferred (returns 0 via None).
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn from_start_records_nonzero_duration_after_sleep() {
        let start = Instant::now();
        thread::sleep(Duration::from_millis(5));
        let metrics = BenchmarkMetrics::from_start(start);
        assert!(
            metrics.duration_ms >= 5,
            "expected at least 5ms, got {}",
            metrics.duration_ms
        );
    }

    #[test]
    fn to_json_line_format() {
        let line = BenchmarkMetrics {
            duration_ms: 42,
            cpu_percent: BENCHMARK_CPU_PERCENT_NOT_SAMPLED,
            mem_mb: 10,
        }
        .to_json_line();
        assert_eq!(
            line,
            r#"{"benchmark":{"duration_ms":42,"cpu_percent":0,"mem_mb":10}}"#
        );
    }

    #[test]
    fn benchmark_max_ms_is_positive() {
        const { assert!(BENCHMARK_MAX_MS > 0) };
    }
}
