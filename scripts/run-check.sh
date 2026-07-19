#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run the full Makefile check gate with CI-quiet defaults and a batched failure
# summary at the end of the log (stderr and GITHUB_STEP_SUMMARY when set).
#
# Usage:
#   ./scripts/run-check.sh
#   ./scripts/run-check.sh --summarize-log /path/to/check.log [--results-dir DIR]
#
# Env (quiet mode, default):
#   VLZ_CHECK_BRIEF=1, RUST_LOG=off, RUST_LOG_STYLE=never
#   PYTEST_ADDOPTS=-q --tb=short
#
# Env (verbose mode, VLZ_CHECK_VERBOSE=1):
#   VLZ_CHECK_BRIEF=0, RUST_LOG=info, RUST_LOG_STYLE=auto, VLZ_COVERAGE_VERBOSE=1
#   PYTEST_ADDOPTS=-v --tb=long, cargo test without --quiet
#
# GitHub Actions: set VLZ_CHECK_VERBOSE=1 when runner.debug is 1 (re-run with
# "Enable debug logging").
#
# Run from repository root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# shellcheck source=lib/check-summary.sh
source "${SCRIPT_DIR}/lib/check-summary.sh"

# shellcheck source=lib/check-quiet-env.sh
source "${SCRIPT_DIR}/lib/check-quiet-env.sh"

if [[ "${1:-}" == "--summarize-log" ]]; then
  log_file=${2:?log path required}
  results_dir=${VLZ_CHECK_RESULTS_DIR:-}
  shift 2 || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --results-dir)
        results_dir=${2:?results dir required}
        shift 2
        ;;
      *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
    esac
  done
  vlz_check_print_failure_summary "$log_file" "$results_dir"
  exit 0
fi

if vlz_check_verbose_enabled; then
  export VLZ_CHECK_BRIEF=0
  export VLZ_COVERAGE_VERBOSE=1
  export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:--v --tb=long}"
else
  export VLZ_CHECK_BRIEF=1
  export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:--q --tb=short}"
fi
vlz_apply_check_log_env

results_dir="${REPO_ROOT}/target/tmp-check-results-$$"
mkdir -p "$results_dir"
export VLZ_CHECK_RESULTS_DIR="$results_dir"
log_file="${results_dir}/check.log"
trap 'rm -rf "$results_dir"' EXIT

set +e
make check 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

if [[ "$status" -eq 0 ]]; then
  echo "check: PASS" >&2
else
  vlz_check_print_failure_summary "$log_file" "$results_dir"
  echo "check: FAIL (exit ${status})" >&2
fi

exit "$status"
