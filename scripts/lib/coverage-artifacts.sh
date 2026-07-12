# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Remove llvm-cov / instrumented-build profraw files under a tree.
# Sourced by scripts/coverage.sh and make clean.
#
# shellcheck shell=bash

# Delete stray *.profraw (gitignored; llvm-cov may leave them in repo root).
vlz_remove_profraw_files() {
  local root="${1:-.}"
  find "${root}" -type f -name '*.profraw' -delete
}

# Post-report Rust coverage artifact cleanup (profraw + llvm-cov workspace state).
vlz_cleanup_rust_coverage_artifacts() {
  local root="${1:-.}"
  cargo llvm-cov clean --workspace 2>/dev/null || true
  vlz_remove_profraw_files "${root}"
}
