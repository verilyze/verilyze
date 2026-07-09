# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Benchmark gate constants (NFR-001, FR-029).
# BENCHMARK_MAX_MS is parsed from the Rust source of truth; do not duplicate.
#
# shellcheck shell=bash

# shellcheck disable=SC2034
BENCHMARK_FIXTURE_MANIFEST_COUNT=200

_benchmark_rust_metrics="${ROOT}/crates/core/vlz/src/benchmark_metrics.rs"

if [[ ! -f "${_benchmark_rust_metrics}" ]]; then
  echo "ERROR: missing ${_benchmark_rust_metrics}" >&2
  exit 1
fi

BENCHMARK_MAX_MS="$(
  sed -n 's/^pub const BENCHMARK_MAX_MS: u64 = \([0-9_]*\);/\1/p' \
    "${_benchmark_rust_metrics}" | tr -d '_'
)"

if [[ -z "${BENCHMARK_MAX_MS}" ]]; then
  echo "ERROR: could not parse BENCHMARK_MAX_MS from benchmark_metrics.rs" >&2
  exit 1
fi
