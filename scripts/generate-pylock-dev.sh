#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate root pylock.dev.toml from pyproject.toml [project.optional-dependencies].dev
# (PEP 751). Requires pip >= 25.1. Used by make generate-pylock-dev and Renovate.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

readonly MIN_PIP_MAJOR=25
readonly MIN_PIP_MINOR=1
readonly OUT_FILE="${ROOT}/pylock.dev.toml"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH" >&2
  exit 1
fi

pip_ver="$(python3 -m pip --version 2>/dev/null | awk '{print $2}')"
if [[ -z "${pip_ver}" ]]; then
  echo "ERROR: could not determine pip version" >&2
  exit 1
fi
pip_major="${pip_ver%%.*}"
pip_rest="${pip_ver#*.}"
pip_minor="${pip_rest%%.*}"
if (( pip_major < MIN_PIP_MAJOR )) ||
  { (( pip_major == MIN_PIP_MAJOR )) && (( pip_minor < MIN_PIP_MINOR )); }; then
  echo "ERROR: pip >= ${MIN_PIP_MAJOR}.${MIN_PIP_MINOR} required for pip lock (found ${pip_ver})" >&2
  exit 1
fi

if ! python3 -m pip lock --help >/dev/null 2>&1; then
  echo "ERROR: pip lock is unavailable (upgrade pip)" >&2
  exit 1
fi

echo "Generating ${OUT_FILE} with pip ${pip_ver} ..."
python3 -m pip lock -e ".[dev]" -o "${OUT_FILE}"
echo "Wrote ${OUT_FILE}"
