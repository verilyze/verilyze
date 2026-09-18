#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# SEC-015 workspace self-scan for CI (supply-chain.yml, verilyze-nightly.yml).
#
# Requires: VLZ_BIN, REPORT_JSON, REPORT_SARIF env vars.
# Optional: GITHUB_WORKSPACE (defaults to repository root).
# Optional: VLZ_REACHABILITY_MODE (when unset, the vlz binary default applies).
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

scan_args=(
  scan "${SCAN_ROOT}"
  --project-id verilyze-ci
  --provider osv
  --format json
  --output "${REPORT_JSON}"
  --report "sarif:${REPORT_SARIF}"
)
if [[ -n "${VLZ_REACHABILITY_MODE:-}" ]]; then
  scan_args+=(--reachability-mode "${VLZ_REACHABILITY_MODE}")
  echo "::notice::verilyze scan reachability_mode=${VLZ_REACHABILITY_MODE}"
else
  echo "::notice::verilyze scan reachability_mode=<binary-default>"
fi
for dir in "${WORKSPACE_SCAN_EXCLUDE_DIRS[@]}"; do
  scan_args+=(--scan-exclude-dir "${dir}")
done

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
