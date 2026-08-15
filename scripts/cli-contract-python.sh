#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Print a Python 3 interpreter path for CLI contract CI (python3, python, py -3).

set -euo pipefail

if command -v python3 >/dev/null 2>&1; then
  command -v python3
  exit 0
fi
if command -v python >/dev/null 2>&1; then
  command -v python
  exit 0
fi
if command -v py >/dev/null 2>&1; then
  py -3 -c "import sys; print(sys.executable)"
  exit 0
fi

echo "error: python3, python, or py -3 is required" >&2
exit 1
