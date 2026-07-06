#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Validate schemas/v1/report.json against golden fixture and live vlz JSON output.
# Run from any cwd (OP-017).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ ! -x "${ROOT}/.venv-test/bin/python" ]]; then
  echo "ERROR: .venv-test missing. Run: make setup" >&2
  exit 1
fi

PYTHONPATH="${ROOT}" "${ROOT}/.venv-test/bin/python" -m pytest \
  "${ROOT}/tests/scripts/test_report_schema.py" -q
