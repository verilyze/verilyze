#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Re-apply vlz scan exit code after artifact/SARIF upload (FR-010).
#
# Usage: SCAN_EXIT=<code> [REPORT_JSON=<path>] ci-enforce-scan-exit.sh

set -euo pipefail

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

if [[ "${SCAN_EXIT}" == "86" ]]; then
  detail="CVEs met the configured threshold (FR-010/FR-014)"
  if [[ -n "${REPORT_JSON:-}" && -f "${REPORT_JSON}" ]]; then
    cve_ids="$(
      python3 - "${REPORT_JSON}" <<'PY'
import json
import sys

path = sys.argv[1]
ids: list[str] = []
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, json.JSONDecodeError):
    print("")
    raise SystemExit(0)
findings = data.get("findings")
if isinstance(findings, list):
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        cves = finding.get("cves")
        if not isinstance(cves, list):
            continue
        for cve in cves:
            if isinstance(cve, dict):
                cve_id = cve.get("id")
                if isinstance(cve_id, str) and cve_id and cve_id not in ids:
                    ids.append(cve_id)
print(",".join(ids))
PY
    )"
    if [[ -n "${cve_ids}" ]]; then
      detail="${detail}: ${cve_ids}"
    fi
  fi
  echo "::error::verilyze scan exit 86 -- ${detail}" >&2
fi

exit "${SCAN_EXIT}"
