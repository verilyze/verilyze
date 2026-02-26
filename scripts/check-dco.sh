#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Verify that all commits in a range contain a Signed-off-by line attesting
# to the Developer Certificate of Origin (DCO).
#
# Usage:
#   ./scripts/check-dco.sh [base_ref] [head_ref]
#
# If base_ref and head_ref are omitted, uses GITHUB_BASE_REF and GITHUB_HEAD_REF
# (or origin/main, else main, and HEAD for local use). For explicit SHA range:
#   ./scripts/check-dco.sh <base_sha> <head_sha>
#
# See https://developercertificate.org/

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not a git repository." >&2
    exit 1
fi

BASE_REF="${1:-}"
HEAD_REF="${2:-}"

if [ -n "$BASE_REF" ] && [ -n "$HEAD_REF" ]; then
    BASE_SHA="$BASE_REF"
    HEAD_SHA="$HEAD_REF"
    # Resolve to full SHAs in case refs were passed
    BASE_SHA="$(git rev-parse "$BASE_SHA")"
    HEAD_SHA="$(git rev-parse "$HEAD_SHA")"
    MERGE_BASE="$(git merge-base "$BASE_SHA" "$HEAD_SHA")"
elif [ -n "${GITHUB_BASE_REF:-}" ] && [ -n "${GITHUB_HEAD_REF:-}" ]; then
    git fetch origin "$GITHUB_BASE_REF" --depth=1 2>/dev/null || true
    MERGE_BASE="$(git merge-base "origin/$GITHUB_BASE_REF" HEAD 2>/dev/null)" || MERGE_BASE=""
    if [ -z "$MERGE_BASE" ]; then
        echo "Error: Could not find merge base for $GITHUB_BASE_REF and HEAD." >&2
        exit 1
    fi
    HEAD_SHA="$(git rev-parse HEAD)"
elif [ -z "$BASE_REF" ] && [ -z "$HEAD_REF" ]; then
    # Local use: check commits from base to HEAD (origin/main or main)
    if git rev-parse origin/main >/dev/null 2>&1; then
        MERGE_BASE="$(git merge-base origin/main HEAD)"
        HEAD_SHA="$(git rev-parse HEAD)"
    elif git rev-parse main >/dev/null 2>&1; then
        MERGE_BASE="$(git merge-base main HEAD)"
        HEAD_SHA="$(git rev-parse HEAD)"
    else
        echo "Error: No base ref. Pass base and head, or run from GitHub Actions." >&2
        exit 1
    fi
else
    echo "Error: Pass both base and head, or neither." >&2
    exit 1
fi

FAILED=0
while read -r sha; do
    if [ -z "$sha" ]; then
        continue
    fi
    if ! git log -1 --format=%B "$sha" | grep -q '^Signed-off-by:'; then
        echo "Commit $sha is missing Signed-off-by. Use 'git commit -s'." >&2
        git log -1 --oneline "$sha" >&2
        FAILED=1
    fi
done < <(git log --format=%H "$MERGE_BASE..$HEAD_SHA" 2>/dev/null || true)

if [ "$FAILED" -eq 1 ]; then
    echo "" >&2
    echo "All commits must include a Signed-off-by line." >&2
    echo "See https://developercertificate.org/" >&2
    echo "Use: git commit -s -m 'your message'" >&2
    exit 1
fi

echo "DCO check passed."
