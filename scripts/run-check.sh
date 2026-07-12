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
# Env (set by this script when unset):
#   RUST_LOG=error
#   PYTEST_ADDOPTS=-q --tb=short
#
# Run from repository root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# shellcheck source=lib/check-summary.sh
source "${SCRIPT_DIR}/lib/check-summary.sh"

if [[ "${1:-}" == "--summarize-log" ]]; then
  vlz_check_print_failure_summary "${2:?log path required}"
  exit 0
fi

export RUST_LOG="${RUST_LOG:-error}"
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:--q --tb=short}"

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
