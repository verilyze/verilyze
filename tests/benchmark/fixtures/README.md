# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Benchmark fixtures (NFR-001, FR-029)

Ephemeral multi-manifest trees for the benchmark gate are generated at runtime by
[`scripts/generate-benchmark-fixture.sh`](../../scripts/generate-benchmark-fixture.sh)
(see [`scripts/benchmark-gate.sh`](../../scripts/benchmark-gate.sh)). The default
count is `BENCHMARK_FIXTURE_MANIFEST_COUNT` in
[`scripts/lib/benchmark_constants.sh`](../../scripts/lib/benchmark_constants.sh).

The duration ceiling is `BENCHMARK_MAX_MS` in
[`crates/core/vlz/src/benchmark_metrics.rs`](../../crates/core/vlz/src/benchmark_metrics.rs).
