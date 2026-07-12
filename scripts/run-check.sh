#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run the full Makefile check gate with CI-quiet defaults and a batched failure
# summary at the end of the log (stderr and GITHUB_STEP_SUMMARY when set).
#
# Usage:
#   ./scripts/run-check.sh
#   ./scripts/run-check.sh --summarize-log /path/to/check.log
#
# Env (quiet mode, default):
#   RUST_LOG=off, RUST_LOG_STYLE=never (via scripts/lib/check-quiet-env.sh)
#   PYTEST_ADDOPTS=-q --tb=short
#
# Env (verbose mode, VLZ_CHECK_VERBOSE=1):
#   RUST_LOG=info, RUST_LOG_STYLE=auto, VLZ_COVERAGE_VERBOSE=1
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
  vlz_check_print_failure_summary "${2:?log path required}"
  exit 0
fi

if vlz_check_verbose_enabled; then
  export VLZ_COVERAGE_VERBOSE=1
  export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:--v --tb=long}"
else
  export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:--q --tb=short}"
fi
vlz_apply_check_log_env

log_file="$(mktemp)"
trap 'rm -f "$log_file"' EXIT

set +e
make check 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

if [[ "$status" -ne 0 ]]; then
  vlz_check_print_failure_summary "$log_file"
fi

exit "$status"
