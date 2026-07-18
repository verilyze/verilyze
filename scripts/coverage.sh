#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate coverage reports using cargo-llvm-cov.
# See: https://docs.rs/crate/cargo-llvm-cov/latest#get-coverage-of-external-tests
#
# Run from the repository root: ./scripts/coverage.sh
#
# Scope (VLZ_COVERAGE_SCOPE):
#   all    - Rust and Python (default; CI / make coverage-quick)
#   rust   - Rust only (make coverage-quick-rust)
#   python - Python only (make coverage-quick-python)

set -e

cd "$(dirname "$0")/.." || exit 1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/check-quiet-env.sh
source "${SCRIPT_DIR}/lib/check-quiet-env.sh"
# shellcheck source=lib/coverage-thresholds.sh
source "${SCRIPT_DIR}/lib/coverage-thresholds.sh"
# shellcheck source=lib/coverage-artifacts.sh
source "${SCRIPT_DIR}/lib/coverage-artifacts.sh"

RUST_REPORT="reports/rust/html/index.html"
PYTHON_REPORT="reports/python/index.html"

VLZ_COVERAGE_SCOPE="${VLZ_COVERAGE_SCOPE:-all}"
case "${VLZ_COVERAGE_SCOPE}" in
  all | rust | python) ;;
  *)
    echo "ERROR: invalid VLZ_COVERAGE_SCOPE=${VLZ_COVERAGE_SCOPE}" \
      "(expected all, rust, or python)" >&2
    exit 1
    ;;
esac

_vlz_cov_phase() {
  if vlz_check_verbose_enabled; then
    echo "[coverage] $(date -Iseconds) $*" >&2
  fi
}

_vlz_cov_quiet_log() {
  vlz_apply_check_log_env
}

_run_rust_coverage() {
  # Always remove profraw/llvm-cov state when this function exits.
  trap 'vlz_cleanup_rust_coverage_artifacts .' RETURN

  # Ensure cargo-llvm-cov and llvm-tools (default/stable toolchain) are available
  command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov \
    --locked
  rustup component add llvm-tools 2>/dev/null || true

  rm -rf reports/rust
  mkdir -p reports/rust

  # Set env for instrumentation; use normal cargo commands per cargo-llvm-cov docs
  # shellcheck source=/dev/null
  source <(cargo llvm-cov show-env --sh)

  # Optional: GNU ld (bfd) for instrument-coverage when rust-lld fails (e.g. invalid
  # symbol index; rust-lang/rust#79555, rust-lang/rust#128938). Off by default: rustc
  # already passes -fuse-ld=lld; adding bfd as well can confuse the linker or trigger
  # bfd crashes (e.g. collect2 bus error) on some Linux toolchains.
  # Set VLZ_COVERAGE_USE_BFD=1 if your coverage build fails with lld.
  if [[ "${VLZ_COVERAGE_USE_BFD:-}" == "1" ]] \
    && [[ "$(uname -s)" == "Linux" ]] \
    && command -v ld.bfd &>/dev/null; then
    export RUSTFLAGS="${RUSTFLAGS} -C link-arg=-fuse-ld=bfd"
  fi

  # Full clean keeps profraw consistent; skip only after proving warm cache is safe.
  _vlz_cov_phase "llvm-cov clean"
  cargo llvm-cov clean --workspace 2>/dev/null || true

  # Build workspace with instrumentation (per show-env docs, use normal cargo).
  # Exclude vlz-fuzz: it requires cargo afl build (AFL linker symbols).
  _vlz_cov_phase "instrumented cargo build --workspace"
  cargo build --workspace --exclude vlz-fuzz

  # Run all workspace tests (exclude vlz-fuzz; it uses AFL and is run via make fuzz).
  _vlz_cov_phase "cargo test --workspace"
  _vlz_cov_quiet_log
  # shellcheck disable=SC2046
  cargo test --workspace --exclude vlz-fuzz --features vlz/testing \
    $(vlz_cargo_test_quiet_arg)

  # Extended pass (nightly / badges): optional features and minimal-feature matrix.
  # Profraw from this pass merges with the default pass above (no llvm-cov clean).
  if [[ "${VLZ_COVERAGE_EXTENDED:-}" == "1" ]]; then
    _vlz_cov_phase "coverage-extended optional features"
    _vlz_cov_quiet_log
    # shellcheck disable=SC2046
    cargo test --workspace --exclude vlz-fuzz \
      --features 'vlz/testing,vlz/perf-instrumentation,vlz/python-tier-d' \
      $(vlz_cargo_test_quiet_arg)
    _vlz_cov_phase "coverage-extended minimal features"
    # shellcheck disable=SC2046
    cargo test -p vlz --no-default-features --features testing \
      --test minimal_features $(vlz_cargo_test_quiet_arg)
  fi

  # Run the vlz binary to capture main.rs and run() coverage (binary is not a
  # test target). Use isolated XDG dirs so we do not touch user config or cache.
  # Omit probes already exercised by cli integration tests (list, config --list).
  run_cov_bin() {
    _vlz_cov_quiet_log
    if vlz_check_verbose_enabled; then
      env XDG_CONFIG_HOME=/tmp/vlz-cov-cfg XDG_CACHE_HOME=/tmp/vlz-cov-cache \
        XDG_DATA_HOME=/tmp/vlz-cov-data cargo run --features vlz/testing \
        --bin vlz -- "$@"
    else
      env XDG_CONFIG_HOME=/tmp/vlz-cov-cfg XDG_CACHE_HOME=/tmp/vlz-cov-cache \
        XDG_DATA_HOME=/tmp/vlz-cov-data cargo run --features vlz/testing \
        --bin vlz -- "$@" >/dev/null
    fi
  }
  _vlz_cov_phase "cargo run binary probes"
  run_cov_bin --version
  run_cov_bin db stats
  run_cov_bin db verify
  run_cov_bin db show --format json
  mkdir -p /tmp/vlz-cov-scan
  run_cov_bin preload /tmp/vlz-cov-scan
  run_cov_bin scan /tmp/vlz-cov-scan --offline --benchmark
  # Error path in main.rs: unknown provider yields exit 2
  run_cov_bin scan /tmp/vlz-cov-scan --offline --provider nonexistentprovider \
    || true

  # Generate Rust reports (NFR-017: fail if coverage below threshold)
  _vlz_cov_phase "llvm-cov report"
  cargo llvm-cov report --html --output-dir reports/rust \
    --fail-under-lines "${VLZ_RUST_FAIL_UNDER_LINES}" \
    --fail-under-functions "${VLZ_RUST_FAIL_UNDER_FUNCTIONS}" \
    --fail-under-regions "${VLZ_RUST_FAIL_UNDER_REGIONS}" \
    || return 1
  cargo llvm-cov report --cobertura --output-path \
    reports/cobertura-rust.xml \
    --fail-under-lines "${VLZ_RUST_FAIL_UNDER_LINES}" \
    --fail-under-functions "${VLZ_RUST_FAIL_UNDER_FUNCTIONS}" \
    --fail-under-regions "${VLZ_RUST_FAIL_UNDER_REGIONS}" \
    || return 1
  return 0
}

_run_python_coverage() {
  PY=python3
  [ -x ".venv-test/bin/python" ] && PY=.venv-test/bin/python
  command -v "$PY" >/dev/null 2>&1 \
    || { echo "ERROR: python3 not found." >&2; return 1; }
  "$PY" -m pytest --version >/dev/null 2>&1 \
    || { echo "ERROR: pytest not found. Run: make setup" >&2; return 1; }
  _vlz_cov_phase "pytest scripts"
  _pytest_cov_report=()
  _pytest_flags=(-q --tb=short)
  if vlz_check_verbose_enabled; then
    _pytest_cov_report+=(--cov-report=term-missing:skip-covered)
    _pytest_flags=(-v --tb=long)
  fi
  mkdir -p reports/python
  PYTHONPATH=. "$PY" -m pytest tests/scripts/ \
    --cov=scripts \
    --cov-report=html:reports/python \
    --cov-report=xml:reports/cobertura-python.xml \
    "${_pytest_cov_report[@]}" \
    --cov-fail-under="${VLZ_PYTHON_FAIL_UNDER_LINES}" \
    "${_pytest_flags[@]}" || return 1

  PYTHONPATH=. "$PY" scripts/coverage_per_file_check.py \
    reports/cobertura-python.xml \
    --min-line-rate "${VLZ_PYTHON_FAIL_UNDER_LINES}" || return 1
  return 0
}

rm -rf reports
rm -f .coverage
find . -name vlz-cache.redb -delete
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
mkdir -p reports

ERR=0

if [[ "${VLZ_COVERAGE_SCOPE}" == "all" || "${VLZ_COVERAGE_SCOPE}" == "rust" ]]; then
  _run_rust_coverage || ERR=1
fi

if [[ "${VLZ_COVERAGE_SCOPE}" == "all" || "${VLZ_COVERAGE_SCOPE}" == "python" ]]; then
  _run_python_coverage || ERR=1
fi

if [[ "${VLZ_COVERAGE_SCOPE}" == "rust" ]]; then
  echo "Coverage report: ${RUST_REPORT} (Rust)"
elif [[ "${VLZ_COVERAGE_SCOPE}" == "python" ]]; then
  echo "Coverage report: ${PYTHON_REPORT} (Python)"
else
  echo "Coverage report: ${RUST_REPORT} (Rust), ${PYTHON_REPORT} (Python)"
fi
exit "$ERR"
