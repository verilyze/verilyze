#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run Python linters (black, pylint, mypy, bandit, modern-style) on scripts/.
# Aggregates failures: runs all five, exits 1 only if any failed.
#
# Usage: ./scripts/lint-python.sh
# Env:   VENV_BIN (optional) - path to venv bin dir, default .venv-lint/bin
#
# Run from repository root.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

V="${VENV_BIN:-.venv-lint/bin}"

# Resolve each tool: venv if runnable, else fall back to system.
resolve_tool() {
  local name=$1
  local venv_path="$V/$name"
  if [ -x "$venv_path" ] 2>/dev/null && \
    "$venv_path" --version >/dev/null 2>&1; then
    echo "$venv_path"
  elif command -v "$name" >/dev/null 2>&1; then
    echo "$name"
  else
    echo "python lint tool not found in venv or PATH: $name" >&2
    return 1
  fi
}

BLACK=$(resolve_tool black)
PYLINT=$(resolve_tool pylint)
MYPY=$(resolve_tool mypy)
BANDIT=$(resolve_tool bandit)
PYTHON=$(resolve_tool python3)

ERR=0

"$PYTHON" scripts/python_modern_style.py || ERR=1

"$BLACK" scripts/ --check --line-length 79 || ERR=1
"$PYLINT" scripts/ --max-line-length=79 || ERR=1
"$MYPY" scripts/ || ERR=1
"$BANDIT" -r scripts/ || ERR=1

exit "$ERR"
