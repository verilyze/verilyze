#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run AFL fuzz targets for verilyze (NFR-020, SEC-017).
#
# Prerequisites (only when targets will run):
#   - cargo-afl:  cargo install cargo-afl
#   - AFL++:      https://github.com/AFLplusplus/AFLplusplus
#
# Usage:
#   ./scripts/fuzz.sh              # Smoke test (all targets)
#   ./scripts/fuzz.sh --changed    # Run only targets for changed code (skip if none)
#   ./scripts/fuzz.sh --changed --dry-run  # Print RUN:targets or SKIP (no AFL)
#   ./scripts/fuzz.sh --targets config_toml,requirements_txt  # Explicit subset
#   ./scripts/fuzz.sh --extended   # Longer timeout (30 min per target)
#   ./scripts/fuzz.sh --coverage   # Run with cargo-llvm-cov integration
#
# FUZZ_TIMEOUT: per-target timeout in seconds. When unset: 30 (smoke) or 1800 (extended).
#
# See CONTRIBUTING.md and https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-afl-fuzzers

set -e

cd "$(dirname "$0")/.." || exit 1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/fuzz-resolve-targets.sh
source "${SCRIPT_DIR}/lib/fuzz-resolve-targets.sh"

# FUZZ_TARGETS_FILE: path to target-to-path map (FUZZ_TARGETS_ENV is a legacy alias).
FUZZ_TARGETS_FILE="${FUZZ_TARGETS_FILE:-${FUZZ_TARGETS_ENV:-$SCRIPT_DIR/fuzz-targets.map}}"
FUZZ_OUT="${FUZZ_OUT:-/tmp/vlz-fuzz-out}"

DO_COVERAGE=false
DO_CHANGED=false
DO_EXTENDED=false
DO_DRY_RUN=false
TARGETS_FILTER=""

for arg in "$@"; do
    case "$arg" in
        --coverage) DO_COVERAGE=true ;;
        --changed) DO_CHANGED=true ;;
        --extended) DO_EXTENDED=true ;;
        --dry-run) DO_DRY_RUN=true ;;
        --targets=*) TARGETS_FILTER="${arg#--targets=}" ;;
    esac
done

# FUZZ_TIMEOUT: override when set; else default 30 (smoke) or 1800 (extended)
if [[ -n "${FUZZ_TIMEOUT:-}" ]]; then
    TIMEOUT_SEC="$FUZZ_TIMEOUT"
elif "$DO_EXTENDED"; then
    TIMEOUT_SEC=1800
else
    TIMEOUT_SEC=30
fi

# Preserve args for error hints (functions below would otherwise see empty $*).
FUZZ_SH_INVOCATION="$*"

# Resolve targets before any AFL bootstrap (fast skip for --changed).
TARGETS_TO_RUN=""
if [[ -n "$TARGETS_FILTER" ]]; then
    TARGETS_TO_RUN=$(fuzz_resolve_targets targets "$TARGETS_FILTER")
elif "$DO_CHANGED"; then
    TARGETS_TO_RUN=$(fuzz_resolve_changed_targets)
else
    TARGETS_TO_RUN=$(fuzz_resolve_targets all)
fi

if [[ -z "$TARGETS_TO_RUN" ]]; then
    if "$DO_COVERAGE"; then
        command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
        cargo llvm-cov report --lcov 2>/dev/null || true
    fi
    if "$DO_DRY_RUN"; then
        echo "SKIP"
    fi
    exit 0
fi

if "$DO_DRY_RUN"; then
    echo "RUN:${TARGETS_TO_RUN}"
    exit 0
fi

# Ensure cargo-afl is available
command -v cargo-afl >/dev/null 2>&1 || cargo install cargo-afl

# AFL++ must be installed; cargo afl build will fail with a clear error if not.

# Bootstrap AFL++ source and the LLVM runtime for this rustc (cargo-afl 0.15+).
# The crates.io cargo-afl-common crate has no bundled AFLplusplus tree;
# --build --update clones into the XDG data dir when the clone is missing.
# After rustup, the LLVM runtime must match the current rustc. We store rustc -vV
# in a stamp under the same afl.rs dir so we run config --build only when it changes,
# not on every fuzz run. Plain --build may fail when AFL was already built; then we
# try --force (see cargo afl config --help).

_afl_rs_data="${XDG_DATA_HOME:-$HOME/.local/share}/afl.rs"
_afl_pp="${_afl_rs_data}/AFLplusplus"
_rustc_stamp="${_afl_rs_data}/rustc-stamp-for-afl"

_afl_verbose=()
if [[ "${VLZ_AFL_VERBOSE:-}" == "1" ]]; then
    _afl_verbose=(--verbose)
fi

_write_rustc_stamp() {
    mkdir -p "$_afl_rs_data"
    rustc -vV > "$_rustc_stamp"
}

_report_afl_config_failed() {
    echo "cargo afl config failed (AFL++ under ${_afl_pp})." >&2
    echo "Retry with: VLZ_AFL_VERBOSE=1 ./scripts/fuzz.sh ${FUZZ_SH_INVOCATION}" >&2
    echo "Debian/Ubuntu packages often required: build-essential llvm-dev clang git" >&2
}

_ensure_afl_runtime_matches_rustc() {
    if [[ -f "$_rustc_stamp" ]] && cmp -s <(rustc -vV) "$_rustc_stamp"; then
        return 0
    fi

    if ! cargo afl config --build "${_afl_verbose[@]}"; then
        if ! cargo afl config --build --force "${_afl_verbose[@]}"; then
            _report_afl_config_failed
            exit 1
        fi
    fi
    _write_rustc_stamp
}

if [[ ! -e "$_afl_pp/.git" ]]; then
    if ! cargo afl config --build --update "${_afl_verbose[@]}"; then
        _report_afl_config_failed
        exit 1
    fi
    _write_rustc_stamp
else
    _ensure_afl_runtime_matches_rustc
fi

# Allow fuzz to run on typical dev systems without root tuning:
# - AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: core_pattern pipes to external utility
# - AFL_SKIP_CPUFREQ: on-demand/powersave CPU governor (some performance drop)
# Override with =0 or unset for strict settings when doing production fuzz runs.
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-1}"
export AFL_SKIP_CPUFREQ="${AFL_SKIP_CPUFREQ:-1}"

mkdir -p "$FUZZ_OUT"
rm -rf "${FUZZ_OUT:?}"/*

if "$DO_COVERAGE"; then
    # cargo-llvm-cov AFL workflow
    command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
    # shellcheck source=/dev/null
    source <(cargo llvm-cov show-env --sh)
    cargo llvm-cov clean --workspace 2>/dev/null || true
fi

# Build fuzz targets with AFL instrumentation.
# -C panic=unwind required so catch_unwind can convert toml parser panics to errors (SEC-017).
if ! "$DO_COVERAGE"; then
    # Plain AFL: do not inherit cargo-llvm-cov show-env (mixing instrument-coverage with
    # cargo afl can SIGILL proc-macros or corrupt target/ when RUSTFLAGS leak in).
    if [[ "${RUSTFLAGS:-}" == *instrument-coverage* ]] \
        || [[ "${RUSTFLAGS:-}" == *sanitizer-coverage* ]]; then
        echo "warning: clearing RUSTFLAGS that look like cargo-llvm-cov for AFL build" >&2
        RUSTFLAGS=""
    fi
fi
export RUSTFLAGS="${RUSTFLAGS:-} -C panic=unwind"
# x86_64: portable CPU level avoids SIGILL in proc-macros when AFL uses sanitizer
# coverage with rustc -C target-cpu=native on some shared runners.
if [[ "$(uname -m)" == "x86_64" ]] && [[ -z "${VLZ_FUZZ_SKIP_TARGET_CPU:-}" ]]; then
    export RUSTFLAGS="${RUSTFLAGS} -C target-cpu=x86-64-v2"
fi
cargo afl build -p vlz-fuzz

run_fuzz() {
    local name=$1
    local bin=$2
    local corpus=$3
    local timeout_sec="${4:-$TIMEOUT_SEC}"
    if "$DO_COVERAGE"; then
        AFL_FUZZER_LOOPCOUNT=20 timeout "$timeout_sec" cargo afl fuzz \
            -i "$corpus" -o "$FUZZ_OUT/$name" -c - -- "target/debug/$bin" || true
    else
        timeout "$timeout_sec" cargo afl fuzz -i "$corpus" -o "$FUZZ_OUT/$name" -c - -- \
            "target/debug/$bin" || true
    fi
}

# Check for crashes and exit 1 if any found (CI-friendly; see FR-009).
check_crashes() {
    local crash_files
    crash_files=$(find "$FUZZ_OUT" -path "*/crashes/*" -type f 2>/dev/null || true)
    if [[ -n "$crash_files" ]]; then
        echo "Fuzz smoke test FAILED: crashes detected in $FUZZ_OUT" >&2
        echo "Crash files:" >&2
        echo "  ${crash_files//$'\n'/$'\n  '}" >&2
        mkdir -p reports
        echo "$crash_files" > reports/fuzz-crashes.txt
        echo "Crash paths written to reports/fuzz-crashes.txt" >&2
        exit 1
    fi
}

# Run selected targets
IFS=',' read -ra TARGET_ARR <<< "$TARGETS_TO_RUN"
for target in "${TARGET_ARR[@]}"; do
    target="${target// }"
    [[ -z "$target" ]] && continue
    bin="fuzz_${target}"
    corpus="tests/fuzz/corpus/${target}"
    if [[ -d "$corpus" ]]; then
        run_fuzz "$target" "$bin" "$corpus"
    else
        echo "Warning: corpus $corpus not found, skipping $target" >&2
    fi
done

check_crashes

if "$DO_COVERAGE"; then
    cargo llvm-cov report --lcov
    echo "Coverage report generated. See cargo-llvm-cov docs for --html, --cobertura, etc."
else
    echo "Fuzz smoke test passed (no crashes)."
fi
