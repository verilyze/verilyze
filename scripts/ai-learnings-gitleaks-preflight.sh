#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Scan an issue/PR comment body with gitleaks before posting to GitHub.
# Usage: ai-learnings-gitleaks-preflight.sh <body-file>
# Exit 0 if clean; non-zero if leaks found or gitleaks missing.
# Does not delete the caller's body file.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${ROOT_DIR}/.gitleaks.toml"

usage() {
  echo "Usage: $0 <body-file>" >&2
  echo "Scan body-file with gitleaks (.gitleaks.toml). Exit 0 if clean." >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

BODY_FILE=$1
if [[ ! -f "${BODY_FILE}" ]]; then
  echo "ERROR: body file not found: ${BODY_FILE}" >&2
  exit 2
fi

if [[ ! -f "${CONFIG}" ]]; then
  echo "ERROR: missing gitleaks config: ${CONFIG}" >&2
  exit 2
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "ERROR: gitleaks is required for AI learnings posts." >&2
  echo "Install: see scripts/gitleaks_native.py hints or make setup." >&2
  exit 1
fi

# Directory scan of a one-file temp dir so --source is always a directory.
SCAN_DIR=
trap 'if [[ -n "${SCAN_DIR}" && -d "${SCAN_DIR}" ]]; then rm -rf "${SCAN_DIR}"; fi' EXIT

SCAN_DIR="$(mktemp -d)"
cp "${BODY_FILE}" "${SCAN_DIR}/body.md"

set +e
gitleaks detect --no-git --no-banner \
  --config "${CONFIG}" \
  --source "${SCAN_DIR}"
ec=$?
set -e

if [[ "${ec}" -ne 0 ]]; then
  echo "ERROR: gitleaks found secrets (or failed). Do not post." >&2
  echo "Redact the body and re-run $0." >&2
  exit "${ec}"
fi

echo "gitleaks: no leaks found in ${BODY_FILE}"
exit 0
