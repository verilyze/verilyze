#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# NFR-001 nightly gate: run vlz --benchmark on a multi-manifest fixture and
# fail when duration_ms exceeds BENCHMARK_MAX_MS (from benchmark_metrics.rs).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# shellcheck source=lib/benchmark_constants.sh
source "${ROOT}/scripts/lib/benchmark_constants.sh"

VLZ_BIN="${VLZ_BIN:-${ROOT}/target/release/vlz}"
if [[ ! -x "${VLZ_BIN}" ]]; then
  VLZ_BIN="${ROOT}/target/debug/vlz"
fi
if [[ ! -x "${VLZ_BIN}" ]]; then
  echo "ERROR: vlz binary not found. Run: make release" >&2
  exit 1
fi

_fixture="$(mktemp -d)"
_cleanup() {
  rm -rf "${_fixture}"
}
trap _cleanup EXIT

"${ROOT}/scripts/generate-benchmark-fixture.sh" \
  "${_fixture}" "${BENCHMARK_FIXTURE_MANIFEST_COUNT}"

_xdg="$(mktemp -d)"
export XDG_CACHE_HOME="${_xdg}"
export XDG_DATA_HOME="${_xdg}"
export XDG_CONFIG_HOME="${_xdg}"

_stdout="$("${VLZ_BIN}" scan "${_fixture}" --offline --benchmark 2>/dev/null || true)"

export BENCHMARK_STDOUT="${_stdout}"
_duration="$(
  PYTHONPATH="${ROOT}" BENCHMARK_STDOUT="${_stdout}" \
    "${ROOT}/.venv-test/bin/python" - <<'PY'
import json
import os
import sys

stdout = os.environ.get("BENCHMARK_STDOUT", "")
line = next((ln for ln in stdout.splitlines() if '"benchmark"' in ln), "")
if not line:
    print("ERROR: no benchmark json line on stdout", file=sys.stderr)
    sys.exit(1)
data = json.loads(line)
print(data["benchmark"]["duration_ms"])
PY
)"

if [[ -z "${_duration}" ]]; then
  echo "ERROR: failed to parse duration_ms" >&2
  exit 1
fi

echo "benchmark duration_ms=${_duration} (max ${BENCHMARK_MAX_MS})"

if [[ "${_duration}" -gt "${BENCHMARK_MAX_MS}" ]]; then
  echo "ERROR: benchmark exceeded NFR-001 ceiling (${_duration}ms > ${BENCHMARK_MAX_MS}ms)" >&2
  exit 1
fi

echo "benchmark gate passed"
