#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Install Git hooks: REUSE headers on new files, diagram embedding on .mmd
# changes, and DCO signoff verification on commit messages.
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

mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/pre-commit" << 'HOOK'
#!/bin/sh
# Installed by scripts/install-hooks.sh - REUSE headers + diagram embedding
cd "$(git rev-parse --show-toplevel)" && exec ./scripts/pre-commit.sh
HOOK
chmod +x "$HOOK_DIR/pre-commit"
echo "Installed pre-commit hook: $HOOK_DIR/pre-commit"

cat > "$HOOK_DIR/commit-msg" << 'HOOK'
#!/bin/sh
# Installed by scripts/install-hooks.sh - DCO signoff verification
cd "$(git rev-parse --show-toplevel)" && exec ./scripts/commit-msg-dco.sh "$1"
HOOK
chmod +x "$HOOK_DIR/commit-msg"
echo "Installed commit-msg hook: $HOOK_DIR/commit-msg"
