#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Ensure reuse is available; run it with the given arguments.
# Resolution order: PATH, .venv/bin/reuse, .venv-reuse/bin/reuse (create if missing),
# pipx run with --spec from scripts/requirements-reuse.txt. Never creates or modifies
# the user's .venv.
#
# Run from repository root: ./scripts/ensure-reuse.sh <args>

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REUSE_REQUIREMENTS="$REPO_ROOT/scripts/requirements-reuse.txt"
cd "$REPO_ROOT"

# pip-compile lists "reuse==X.Y.Z \"; pipx --spec needs the line without continuation.
reuse_pypi_spec() {
    local line
    line=$(grep -E '^reuse==' "$REUSE_REQUIREMENTS" | head -n1) || return 1
    printf '%s\n' "$line" | sed 's/[[:space:]]*\\$//' | sed 's/[[:space:]]*$//'
}

# 1. reuse in PATH
if command -v reuse >/dev/null 2>&1 && reuse --help >/dev/null 2>&1; then
    exec reuse "$@"
fi

# 2. .venv/bin/reuse (read-only; never create or modify .venv)
if [ -x ".venv/bin/reuse" ] && .venv/bin/reuse --help >/dev/null 2>&1; then
    exec .venv/bin/reuse "$@"
fi

# 3. .venv-reuse/bin/reuse (create venv and install if missing or broken)
if [ ! -f "$REUSE_REQUIREMENTS" ]; then
    echo "ERROR: missing $REUSE_REQUIREMENTS (hash-pinned REUSE lockfile)." >&2
    exit 1
fi
if [ -x ".venv-reuse/bin/reuse" ] && .venv-reuse/bin/reuse --help >/dev/null 2>&1; then
    exec .venv-reuse/bin/reuse "$@"
fi
# .venv-reuse missing or broken (e.g. venv created but pip install failed)
if [ -d ".venv-reuse" ]; then
    rm -rf .venv-reuse
fi
if python3 -m venv .venv-reuse && .venv-reuse/bin/pip install --quiet --require-hashes -r "$REUSE_REQUIREMENTS"; then
    exec .venv-reuse/bin/reuse "$@"
fi

# 4. pipx run reuse (spec matches lockfile; same pin as pip install)
if command -v pipx >/dev/null 2>&1; then
    REUSE_SPEC=$(reuse_pypi_spec) || {
        echo "ERROR: could not read reuse pin from $REUSE_REQUIREMENTS" >&2
        exit 1
    }
    exec pipx run --spec "$REUSE_SPEC" reuse "$@"
fi

echo "ERROR: 'reuse' is not installed and could not be auto-installed." >&2
echo "  Install via: pipx install reuse" >&2
echo "  Or: python3 -m venv .venv-reuse && .venv-reuse/bin/pip install --require-hashes -r scripts/requirements-reuse.txt" >&2
exit 1
