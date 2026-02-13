#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate coverage reports using cargo-llvm-cov.
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

# Build workspace with instrumentation (per show-env docs, use normal cargo).
# Exclude spd-fuzz: it requires cargo afl build (AFL linker symbols).
cargo +nightly build --workspace --exclude spd-fuzz

# Verify REUSE compliance (headers)
./scripts/ensure-reuse.sh lint

# Run all workspace tests (exclude spd-fuzz; it uses AFL and is run via make fuzz).
cargo +nightly test --workspace --exclude spd-fuzz

# Generate reports (NFR-017: fail if coverage below threshold)
cargo +nightly llvm-cov report --html --output-dir reports \
  --fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85
cargo +nightly llvm-cov report --cobertura --output-path reports/cobertura.xml \
  --fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85

echo "Coverage report: reports/index.html"
