#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run AFL fuzz targets for verilyze (NFR-020, SEC-017).
#
# Prerequisites:
#   - cargo-afl:  cargo install cargo-afl
#   - AFL++:      https://github.com/AFLplusplus/AFLplusplus
#
# Usage:
#   ./scripts/fuzz.sh              # Smoke test (all targets)
#   ./scripts/fuzz.sh --changed    # Run only targets for changed code (skip if none)
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
FUZZ_TARGETS_ENV="${FUZZ_TARGETS_ENV:-$SCRIPT_DIR/fuzz-targets.env}"
FUZZ_OUT="${FUZZ_OUT:-/tmp/vlz-fuzz-out}"

DO_COVERAGE=false
DO_CHANGED=false
DO_EXTENDED=false
TARGETS_FILTER=""

for arg in "$@"; do
    case "$arg" in
        --coverage) DO_COVERAGE=true ;;
        --changed) DO_CHANGED=true ;;
        --extended) DO_EXTENDED=true ;;
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

# Ensure cargo-afl is available
command -v cargo-afl >/dev/null 2>&1 || cargo install cargo-afl

# AFL++ must be installed; cargo afl build will fail with a clear error if not.

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
export RUSTFLAGS="${RUSTFLAGS} -C panic=unwind"
cargo afl build -p vlz-fuzz

# Load target-to-path mapping from fuzz-targets.env.
# Format: target_name=path (one per line; # for comments)
# bin = fuzz_${target_name}, corpus = tests/fuzz/corpus/${target_name}
get_all_targets() {
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line// }"
        [[ -z "$line" ]] && continue
        if [[ "$line" == *=* ]]; then
            echo "${line%%=*}"
        fi
    done < "$FUZZ_TARGETS_ENV"
}

# Resolve which targets to run.
TARGETS_TO_RUN=""
if [[ -n "$TARGETS_FILTER" ]]; then
    # Explicit --targets=list
    TARGETS_TO_RUN="$TARGETS_FILTER"
elif "$DO_CHANGED"; then
    # Change detection: run only targets whose mapped paths changed, or all if unclear
    BASE_REF=""
    if ref=$(git rev-parse --abbrev-ref 'HEAD@{upstream}' 2>/dev/null); then
        BASE_REF=$(git merge-base HEAD "origin/$ref" 2>/dev/null || true)
    fi
    [[ -z "$BASE_REF" ]] && BASE_REF=$(git merge-base HEAD origin/main 2>/dev/null || true)
    [[ -z "$BASE_REF" ]] && BASE_REF=$(git merge-base HEAD main 2>/dev/null || true)
    [[ -z "$BASE_REF" ]] && BASE_REF="main"

    CHANGED_FILES=""
    if [[ -n "$BASE_REF" ]] && git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
        CHANGED_FILES=$(git diff --name-only "$BASE_REF"..HEAD 2>/dev/null || true)
    fi

    if [[ -z "$CHANGED_FILES" ]] && [[ -z "$BASE_REF" ]]; then
        echo "Running all fuzz targets (change detection inconclusive)." >&2
        TARGETS_TO_RUN=$(get_all_targets | tr '\n' ',')
        TARGETS_TO_RUN="${TARGETS_TO_RUN%,}"
    elif [[ -n "$CHANGED_FILES" ]]; then
        # Shared crates: any change triggers "run all"
        SHARED_PATTERNS="crates/core/vlz-db/ crates/db-backends/vlz-db-redb/ crates/core/vlz-plugin-macro/"
        RUN_ALL=false
        for f in $CHANGED_FILES; do
            for p in $SHARED_PATTERNS; do
                if [[ "$f" == "$p"* ]]; then
                    RUN_ALL=true
                    break 2
                fi
            done
            if [[ "$f" == tests/fuzz/* ]] || [[ "$f" == "Cargo.toml" ]] ||
                [[ "$f" == "Cargo.lock" ]]; then
                RUN_ALL=true
                break
            fi
        done

        if "$RUN_ALL"; then
            echo "Running all fuzz targets (shared/fuzz/crate changes)." >&2
            TARGETS_TO_RUN=$(get_all_targets | tr '\n' ',')
            TARGETS_TO_RUN="${TARGETS_TO_RUN%,}"
        else
            # Match changed files to target paths
            matched=""
            while IFS= read -r line || [[ -n "$line" ]]; do
                line="${line%%#*}"
                line="${line// }"
                [[ -z "$line" ]] || [[ "$line" != *=* ]] && continue
                target="${line%%=*}"
                path="${line#*=}"
                for f in $CHANGED_FILES; do
                    if [[ "$f" == "$path" ]] || [[ "$f" == "$path"* ]]; then
                        matched="${matched:+$matched,}$target"
                        break
                    fi
                done
            done < "$FUZZ_TARGETS_ENV"
            if [[ -z "$matched" ]]; then
                echo "No mapped files changed; skipping fuzz (exit 0)." >&2
                if "$DO_COVERAGE"; then
                    cargo llvm-cov report --lcov 2>/dev/null || true
                fi
                exit 0
            fi
            TARGETS_TO_RUN="$matched"
            echo "Running fuzz targets for changed code: $TARGETS_TO_RUN" >&2
        fi
    else
        echo "No mapped files changed; skipping fuzz (exit 0)." >&2
        if "$DO_COVERAGE"; then
            cargo llvm-cov report --lcov 2>/dev/null || true
        fi
        exit 0
    fi
else
    # Default: run all targets
    TARGETS_TO_RUN=$(get_all_targets | tr '\n' ',')
    TARGETS_TO_RUN="${TARGETS_TO_RUN%,}"
fi

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
