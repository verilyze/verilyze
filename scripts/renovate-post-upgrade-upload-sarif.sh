#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Sync examples/github-action-vlz-scan.yml upload-sarif pin from supply-chain.yml
# after any github-actions update (Renovate postUpgradeTasks).
# Match the github-actions manager, not github/codeql-action/upload-sarif:
# Renovate reports that uses: line as package github/codeql-action.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH" >&2
  exit 1
fi

PYTHONPATH="${ROOT}" python3 "${ROOT}/scripts/upload_sarif_pins.py"
