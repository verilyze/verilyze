#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run one check command with brief CI output: [RUN]/[PASS]/[FAIL] plus captured
# diagnostics on failure. Streams when VLZ_CHECK_VERBOSE=1 or VLZ_CHECK_BRIEF!=1.
#
# Usage: ./scripts/run-check-command.sh <label> -- <command...>
#
# Env: VLZ_CHECK_RESULTS_DIR (optional) - store failed command captures for
#      end-of-run summary (see scripts/lib/check-summary.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=lib/check-quiet-env.sh
source "${SCRIPT_DIR}/lib/check-quiet-env.sh"

# shellcheck source=lib/check-summary.sh
source "${SCRIPT_DIR}/lib/check-summary.sh"

capture_temp_dir() {
  if [[ -n "${VLZ_CHECK_RESULTS_DIR:-}" ]]; then
    printf '%s\n' "$VLZ_CHECK_RESULTS_DIR"
    return 0
  fi
  printf '%s\n' "${REPO_ROOT}/target/tmp-check-capture"
}

usage() {
  echo "usage: $0 <label> -- <command...>" >&2
  exit 2
}

runner_error() {
  local reason=$1
  echo "[ERROR] ${label} (${reason})" >&2
  exit 1
}

[[ $# -ge 1 ]] || usage
label=$1
shift
[[ "${1:-}" == "--" ]] || usage
shift
[[ $# -ge 1 ]] || usage

run_streaming() {
  echo "[RUN] ${label}"
  set +e
  "$@"
  local ec=$?
  set -e
  if [[ "$ec" -eq 0 ]]; then
    echo "[PASS] ${label}"
  else
    echo "[FAIL] ${label} (exit ${ec})"
  fi
  return "$ec"
}

run_brief() {
  local capture_dir
  capture_dir="$(capture_temp_dir)"
  mkdir -p "$capture_dir" || runner_error "mkdir failed: ${capture_dir}"
  local capture
  capture="$(mktemp "${capture_dir}/capture.XXXXXX")" \
    || runner_error "mktemp failed in ${capture_dir}"
  echo "[RUN] ${label}"
  set +e
  "$@" >"$capture" 2>&1
  local ec=$?
  set -e
  if [[ "$ec" -eq 0 ]]; then
    rm -f "$capture"
    echo "[PASS] ${label}"
    return 0
  fi
  echo "[FAIL] ${label} (exit ${ec})"
  cat "$capture"
  if [[ -n "${VLZ_CHECK_RESULTS_DIR:-}" ]]; then
    vlz_check_record_failure "$label" "$ec" "$capture"
  fi
  rm -f "$capture"
  return "$ec"
}

# Brief capture when VLZ_CHECK_BRIEF=1 and not verbose; otherwise stream.
if vlz_check_brief_enabled; then
  run_brief "$@"
else
  run_streaming "$@"
fi
