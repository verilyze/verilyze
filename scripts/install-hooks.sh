#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Install Git hooks: REUSE headers on new files, diagram embedding on .mmd
# changes, DCO signoff verification on commit messages, and signature
# verification on push.
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

cat > "$HOOK_DIR/pre-push" << 'HOOK'
#!/bin/sh
# Installed by scripts/install-hooks.sh - commit signature verification
# Reads standard pre-push stdin and checks signatures for commits about
# to be pushed. Uses strict mode (requires valid G or U signature).
cd "$(git rev-parse --show-toplevel)" || exit 1

ZERO="0000000000000000000000000000000000000000"

while read -r local_ref local_sha remote_ref remote_sha; do
    if [ "$local_sha" = "$ZERO" ]; then
        # Deleting a remote branch; nothing to check.
        continue
    fi
    if [ "$remote_sha" = "$ZERO" ]; then
        # New branch: check from merge base with origin/main.
        base="$(git merge-base origin/main "$local_sha" 2>/dev/null)" || base=""
        if [ -z "$base" ]; then
            base="$(git merge-base main "$local_sha" 2>/dev/null)" || base=""
        fi
        if [ -z "$base" ]; then
            echo "Warning: could not find base for new branch; skipping signature check." >&2
            continue
        fi
    else
        base="$remote_sha"
    fi
    exec ./scripts/check-signatures.sh "$base" "$local_sha"
done
HOOK
chmod +x "$HOOK_DIR/pre-push"
echo "Installed pre-push hook: $HOOK_DIR/pre-push"
