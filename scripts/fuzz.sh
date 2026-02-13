#!/usr/bin/env bash
# Run AFL fuzz targets for super-duper (NFR-020, SEC-017).
#
# Prerequisites:
#   - cargo-afl:  cargo install cargo-afl
#   - AFL++:      https://github.com/AFLplusplus/AFLplusplus
#
# Usage:
#   ./scripts/fuzz.sh              # Smoke test (short run)
#   ./scripts/fuzz.sh --coverage   # Run with cargo-llvm-cov integration
#
# See CONTRIBUTING.md and https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-afl-fuzzers

set -e

cd "$(dirname "$0")/.." || exit 1

FUZZ_OUT="${FUZZ_OUT:-/tmp/spd-fuzz-out}"
SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-30}"
DO_COVERAGE=false

for arg in "$@"; do
    case "$arg" in
        --coverage) DO_COVERAGE=true ;;
    esac
done

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
cargo afl build -p spd-fuzz

CORPUS_CONFIG="tests/fuzz/corpus/config_toml"
CORPUS_REQS="tests/fuzz/corpus/requirements_txt"

run_fuzz() {
    local name=$1
    local bin=$2
    local corpus=$3
    local timeout_sec="${4:-$SMOKE_TIMEOUT}"
    if "$DO_COVERAGE"; then
        AFL_FUZZER_LOOPCOUNT=20 timeout "$timeout_sec" cargo afl fuzz \
            -i "$corpus" -o "$FUZZ_OUT/$name" -c - -- "target/debug/$bin" || true
    else
        timeout "$timeout_sec" cargo afl fuzz -i "$corpus" -o "$FUZZ_OUT/$name" -c - -- \
            "target/debug/$bin" || true
    fi
}

if "$DO_COVERAGE"; then
    echo "Running fuzz with coverage (each target ${SMOKE_TIMEOUT}s)..."
    run_fuzz config_toml fuzz_config_toml "$CORPUS_CONFIG"
    run_fuzz requirements_txt fuzz_requirements_txt "$CORPUS_REQS"
    cargo llvm-cov report --lcov
    echo "Coverage report generated. See cargo-llvm-cov docs for --html, --cobertura, etc."
else
    echo "Running fuzz smoke test (${SMOKE_TIMEOUT}s per target)..."
    run_fuzz config_toml fuzz_config_toml "$CORPUS_CONFIG"
    run_fuzz requirements_txt fuzz_requirements_txt "$CORPUS_REQS"
    echo "Fuzz smoke test passed (no crashes)."
fi
