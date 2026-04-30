// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

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

pub fn should_skip_dir(path: &Path, exclude: &HashSet<String>) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| exclude.contains(name))
        .unwrap_or(false)
}

pub fn list_files_with_ext(
    root: &Path,
    exclude_dir_names: &HashSet<String>,
    ext: &str,
) -> std::io::Result<Vec<PathBuf>> {
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
    Ok(out)
}
