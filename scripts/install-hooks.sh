#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Install Git hooks: REUSE headers on new files, diagram embedding on .mmd changes.
# Copies the pre-commit hook into .git/hooks/pre-commit.
#
# Run from repository root: ./scripts/install-hooks.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Not a git repository." >&2
    exit 1
fi

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

mkdir -p "$HOOK_DIR"
cat > "$HOOK_FILE" << 'HOOK'
#!/bin/sh
# Installed by scripts/install-hooks.sh - REUSE headers + diagram embedding
cd "$(git rev-parse --show-toplevel)" && exec ./scripts/pre-commit.sh
HOOK
chmod +x "$HOOK_FILE"
echo "Installed pre-commit hook: $HOOK_FILE"
