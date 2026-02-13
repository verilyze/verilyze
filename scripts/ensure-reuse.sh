#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Ensure reuse is available; run it with the given arguments.
# Resolution order: PATH, .venv/bin/reuse, .venv-reuse/bin/reuse (create if missing),
# pipx run reuse. Never creates or modifies the user's .venv.
#
# Run from repository root: ./scripts/ensure-reuse.sh <args>

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# 1. reuse in PATH
if command -v reuse >/dev/null 2>&1 && reuse --help >/dev/null 2>&1; then
    exec reuse "$@"
fi

# 2. .venv/bin/reuse (read-only; never create or modify .venv)
if [ -x ".venv/bin/reuse" ] && .venv/bin/reuse --help >/dev/null 2>&1; then
    exec .venv/bin/reuse "$@"
fi

# 3. .venv-reuse/bin/reuse (create venv and install if missing)
if [ -x ".venv-reuse/bin/reuse" ] && .venv-reuse/bin/reuse --help >/dev/null 2>&1; then
    exec .venv-reuse/bin/reuse "$@"
fi
if ! [ -d ".venv-reuse" ]; then
    python3 -m venv .venv-reuse
    .venv-reuse/bin/pip install --quiet reuse
    exec .venv-reuse/bin/reuse "$@"
fi

# 4. pipx run reuse
if command -v pipx >/dev/null 2>&1; then
    exec pipx run reuse "$@"
fi

echo "ERROR: 'reuse' is not installed and could not be auto-installed." >&2
echo "  Install via: pipx install reuse" >&2
echo "  Or: python3 -m venv .venv-reuse && .venv-reuse/bin/pip install reuse" >&2
exit 1
