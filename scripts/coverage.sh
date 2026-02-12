#!/usr/bin/env bash
# Generate coverage reports using cargo-llvm-cov.
# Uses the "external tests" workflow so the xtask binary can be invoked directly.
# See: https://docs.rs/crate/cargo-llvm-cov/latest#get-coverage-of-external-tests
#
# Run from the repository root: ./scripts/coverage.sh

set -e

cd "$(dirname "$0")/.." || exit 1

# Ensure cargo-llvm-cov and nightly are available
command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
rustup toolchain install nightly 2>/dev/null || true
rustup component add llvm-tools --toolchain nightly 2>/dev/null || true

rm -rf reports
find . -name spd-cache.redb -delete
mkdir -p reports

# Set env for instrumentation; use normal cargo commands per cargo-llvm-cov docs
# shellcheck source=/dev/null
source <(cargo +nightly llvm-cov show-env --sh)
cargo +nightly llvm-cov clean --workspace 2>/dev/null || true

# Build workspace with instrumentation (per show-env docs, use normal cargo)
cargo +nightly build --workspace

XTASK=target/debug/xtask

# Run xtask check (from project root)
"$XTASK" check

# Run xtask from empty dir to cover unwrap_or_else error path in main.rs
XTASK_FAIL=$(mktemp -d)
XTASK_ROOT="$XTASK_FAIL" "$XTASK" check 2>/dev/null || true

# Run xtask replace from temp dir to cover write_if_changed and replace branch
XTASK_COVER=$(mktemp -d)
mkdir -p "$XTASK_COVER/tools"
echo "// header" > "$XTASK_COVER/tools/header.txt"
echo 'fn main() {}' > "$XTASK_COVER/foo.rs"
XTASK_ROOT="$XTASK_COVER" "$XTASK" replace 1>/dev/null 2>/dev/null

# Run all workspace tests
cargo +nightly test --workspace

# Generate reports (NFR-017: fail if coverage below threshold)
cargo +nightly llvm-cov report --html --output-dir reports \
  --fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85
cargo +nightly llvm-cov report --cobertura --output-path reports/cobertura.xml \
  --fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85

echo "Coverage report: reports/index.html"
