#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Emit SEC-015 scan metrics to workflow logs and optional GITHUB_OUTPUT.
#
# shellcheck shell=bash

ci_verilyze_count_json_findings() {
  local report_json="$1"
  python3 - "${report_json}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, json.JSONDecodeError):
    print(0)
else:
    findings = data.get("findings")
    print(len(findings) if isinstance(findings, list) else 0)
PY
}

ci_verilyze_count_sarif_results() {
  local report_sarif="$1"
  python3 - "${report_sarif}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, json.JSONDecodeError):
    print(0)
else:
  total = 0
  for run in data.get("runs", []):
      results = run.get("results")
      if isinstance(results, list):
          total += len(results)
  print(total)
PY
}

ci_verilyze_emit_scan_metrics() {
  local report_json="$1"
  local report_sarif="$2"
  local duration_seconds="$3"
  local scan_exit="$4"

  local finding_count=0
  local sarif_result_count=0

  if [[ -f "${report_json}" ]]; then
    finding_count="$(ci_verilyze_count_json_findings "${report_json}")"
  fi
  if [[ -f "${report_sarif}" ]]; then
    sarif_result_count="$(ci_verilyze_count_sarif_results "${report_sarif}")"
  fi

  echo "::notice::verilyze scan duration=${duration_seconds}s findings=${finding_count} sarif_results=${sarif_result_count} exit=${scan_exit}"

  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      echo "scan_duration_seconds=${duration_seconds}"
      echo "finding_count=${finding_count}"
      echo "sarif_result_count=${sarif_result_count}"
      echo "scan_exit=${scan_exit}"
    } >> "${GITHUB_OUTPUT}"
  fi
}
