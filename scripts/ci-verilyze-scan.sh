#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# SEC-015 workspace self-scan for CI (supply-chain.yml, verilyze-nightly.yml).
#
# Requires: VLZ_BIN, REPORT_JSON, REPORT_SARIF env vars.
# Optional: GITHUB_WORKSPACE (defaults to repository root).
# Optional: VLZ_REACHABILITY_MODE (default tier-b).
#
# Callers must set VLZ_BIN to a verified release binary (nightly) or a freshly
# built PR binary (supply-chain.yml after make release).
#
# Writes scan metrics to GITHUB_OUTPUT when set (scan_exit, counts, duration).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/workspace-scan-excludes.sh
source "${ROOT}/scripts/lib/workspace-scan-excludes.sh"
# shellcheck source=lib/ci-verilyze-scan-metrics.sh
source "${ROOT}/scripts/lib/ci-verilyze-scan-metrics.sh"

: "${VLZ_BIN:?VLZ_BIN is required}"
: "${REPORT_JSON:?REPORT_JSON is required}"
: "${REPORT_SARIF:?REPORT_SARIF is required}"

if [[ ! -x "${VLZ_BIN}" ]]; then
  echo "::error::VLZ_BIN is not executable: ${VLZ_BIN}" >&2
  exit 1
fi

SCAN_ROOT="${GITHUB_WORKSPACE:-$ROOT}"
: "${VLZ_REACHABILITY_MODE:=tier-b}"

scan_args=(
  scan "${SCAN_ROOT}"
  --project-id verilyze-ci
  --provider osv
  --format json
  --reachability-mode "${VLZ_REACHABILITY_MODE}"
  --summary-file "json:${REPORT_JSON}"
  --summary-file "sarif:${REPORT_SARIF}"
)
for dir in "${WORKSPACE_SCAN_EXCLUDE_DIRS[@]}"; do
  scan_args+=(--scan-exclude-dir "${dir}")
done

echo "::notice::verilyze scan reachability_mode=${VLZ_REACHABILITY_MODE}"
start_epoch="$(date +%s)"
set +e
"${VLZ_BIN}" "${scan_args[@]}"
scan_exit=$?
set -e
end_epoch="$(date +%s)"
duration_seconds=$((end_epoch - start_epoch))

ci_verilyze_emit_scan_metrics \
  "${REPORT_JSON}" \
  "${REPORT_SARIF}" \
  "${duration_seconds}" \
  "${scan_exit}"

exit "${scan_exit}"
