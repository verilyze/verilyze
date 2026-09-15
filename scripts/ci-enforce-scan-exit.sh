#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Re-apply vlz scan exit code after artifact/SARIF upload (FR-010).
#
# Usage: SCAN_EXIT=<code> [REPORT_JSON=<path>] ci-enforce-scan-exit.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ci-verilyze-scan-metrics.sh
source "${SCRIPT_DIR}/lib/ci-verilyze-scan-metrics.sh"

: "${SCAN_EXIT:?SCAN_EXIT is required}"

case "${SCAN_EXIT}" in
  *[!0-9]*)
    echo "::error::invalid scan exit code: ${SCAN_EXIT}" >&2
    exit 1
    ;;
esac

if (( SCAN_EXIT > 255 )); then
  echo "::error::scan exit code out of range: ${SCAN_EXIT}" >&2
  exit 1
fi

ci_verilyze_emit_cve_threshold_error \
  "${SCAN_EXIT}" "${REPORT_JSON:-}" 0 stderr

exit "${SCAN_EXIT}"
