#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate coverage reports using cargo-llvm-cov.
# See: https://docs.rs/crate/cargo-llvm-cov/latest#get-coverage-of-external-tests
#
# Run from the repository root: ./scripts/coverage.sh

set -e

cd "$(dirname "$0")/.." || exit 1

RUST_REPORT="reports/rust/html/index.html"
PYTHON_REPORT="reports/python/index.html"

# Ensure cargo-llvm-cov and nightly are available
command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov \
  --locked
rustup toolchain install nightly 2>/dev/null || true
rustup component add llvm-tools --toolchain nightly 2>/dev/null || true

rm -rf reports
rm -f .coverage
find . -name vlz-cache.redb -delete
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
mkdir -p reports/rust

# Set env for instrumentation; use normal cargo commands per cargo-llvm-cov docs
# shellcheck source=/dev/null
source <(cargo +nightly llvm-cov show-env --sh)
cargo +nightly llvm-cov clean --workspace 2>/dev/null || true

# Build workspace with instrumentation (per show-env docs, use normal cargo).
# Exclude vlz-fuzz: it requires cargo afl build (AFL linker symbols).
cargo +nightly build --workspace --exclude vlz-fuzz

# Verify REUSE compliance (headers)
./scripts/ensure-reuse.sh lint

# Run all workspace tests (exclude vlz-fuzz; it uses AFL and is run via make fuzz).
cargo +nightly test --workspace --exclude vlz-fuzz

# Run the vlz binary to capture main.rs and run() coverage (binary is not a
# test target). Use isolated XDG dirs so we do not touch user config or cache.
run_cov_bin() {
  env XDG_CONFIG_HOME=/tmp/vlz-cov-cfg XDG_CACHE_HOME=/tmp/vlz-cov-cache \
    XDG_DATA_HOME=/tmp/vlz-cov-data cargo +nightly run --bin vlz -- "$@"
}
run_cov_bin version
run_cov_bin -v version
run_cov_bin list
run_cov_bin config --list
run_cov_bin db stats
run_cov_bin db verify
run_cov_bin db show --format json
run_cov_bin preload
mkdir -p /tmp/vlz-cov-scan
run_cov_bin scan /tmp/vlz-cov-scan --offline --benchmark
# Error path in main.rs: unknown provider yields exit 2
run_cov_bin scan /tmp/vlz-cov-scan --offline --provider nonexistentprovider \
  || true

# Generate Rust reports (NFR-017: fail if coverage below threshold)
# Use || true so script continues to Python coverage even when Rust fails
ERR=0
cargo +nightly llvm-cov report --html --output-dir reports/rust \
  --fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85 \
  || ERR=1
cargo +nightly llvm-cov report --cobertura --output-path reports/cobertura.xml \
  --fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85 \
  || ERR=1

# Script coverage (NFR-012, NFR-017): pytest-cov for scripts/
PY=python3
[ -x ".venv-test/bin/python" ] && PY=.venv-test/bin/python
command -v "$PY" >/dev/null 2>&1 \
  || { echo "ERROR: python3 not found." >&2; exit 1; }
"$PY" -m pytest --version >/dev/null 2>&1 \
  || { echo "ERROR: pytest not found. Run: pip install pytest pytest-cov" >&2; exit 1; }
PYTHONPATH=. "$PY" -m pytest tests/scripts/ \
  --cov=scripts \
  --cov-report=html:reports/python \
  --cov-report=xml:reports/cobertura-python.xml \
  --cov-fail-under=85 \
  -v || ERR=1

echo "Coverage report: $RUST_REPORT (Rust), $PYTHON_REPORT (Python)"
exit "$ERR"
