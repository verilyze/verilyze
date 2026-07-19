# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Quiet and verbose log defaults for CI checks and coverage test runs.
# Sourced by scripts/run-check.sh, scripts/coverage.sh, and generate-sbom.sh.
#
# shellcheck shell=bash

readonly VLZ_QUIET_RUST_LOG=off
readonly VLZ_QUIET_RUST_LOG_STYLE=never
readonly VLZ_VERBOSE_RUST_LOG=info
readonly VLZ_VERBOSE_RUST_LOG_STYLE=auto

# True when VLZ_CHECK_VERBOSE=1 (CI debug re-run) or VLZ_COVERAGE_VERBOSE=1.
vlz_check_verbose_enabled() {
  [[ "${VLZ_CHECK_VERBOSE:-}" == "1" || "${VLZ_COVERAGE_VERBOSE:-}" == "1" ]]
}

# Brief command-level output (default for CI check unless verbose).
vlz_check_brief_enabled() {
  if vlz_check_verbose_enabled; then
    return 1
  fi
  [[ "${VLZ_CHECK_BRIEF:-0}" == "1" ]]
}

# Export RUST_LOG/RUST_LOG_STYLE for cargo test and batch vlz probes.
# Does not affect eprintln! (e.g. vlz warning: FR-022a).
vlz_export_check_quiet_log_env() {
  export RUST_LOG="${VLZ_QUIET_RUST_LOG}"
  export RUST_LOG_STYLE="${VLZ_QUIET_RUST_LOG_STYLE}"
}

vlz_export_check_verbose_log_env() {
  export RUST_LOG="${VLZ_VERBOSE_RUST_LOG}"
  export RUST_LOG_STYLE="${VLZ_VERBOSE_RUST_LOG_STYLE}"
}

vlz_apply_check_log_env() {
  if vlz_check_verbose_enabled; then
    vlz_export_check_verbose_log_env
  else
    vlz_export_check_quiet_log_env
  fi
}

# Echo --quiet for cargo test when checks run in quiet mode.
vlz_cargo_test_quiet_arg() {
  if vlz_check_verbose_enabled; then
    return 0
  fi
  echo --quiet
}
