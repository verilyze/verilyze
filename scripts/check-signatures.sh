#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Verify that all commits in a range have a valid cryptographic signature
# (GPG or SSH). Backend-agnostic: uses git's %G? status codes, which are
# the same regardless of signing method.
#
# Two modes:
#   Strict (default): requires G (good) or U (good, unknown trust).
#   Presence-only:    requires any signature (rejects only N = unsigned).
#
# Usage:
#   ./scripts/check-signatures.sh [--presence-only] [base_ref] [head_ref]
#
# If base_ref and head_ref are omitted, uses GITHUB_BASE_REF and
# GITHUB_HEAD_REF (or origin/main, else main, and HEAD for local use).
#
# Uses --first-parent traversal so that commits brought in through
# merge second-parents (e.g. GitHub-signed merge commits on main) are
# not re-checked. See CONTRIBUTING.md for rationale.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not a git repository." >&2
    exit 1
fi

# Parse optional --presence-only flag
PRESENCE_ONLY=0
if [[ "${1:-}" == "--presence-only" ]]; then
    PRESENCE_ONLY=1
    shift
fi

BASE_REF="${1:-}"
HEAD_REF="${2:-}"

if [[ -n "$BASE_REF" ]] && [[ -n "$HEAD_REF" ]]; then
    BASE_SHA="$(git rev-parse "$BASE_REF")"
    HEAD_SHA="$(git rev-parse "$HEAD_REF")"
    MERGE_BASE="$(git merge-base "$BASE_SHA" "$HEAD_SHA")"
elif [[ -n "${GITHUB_BASE_REF:-}" ]] && [[ -n "${GITHUB_HEAD_REF:-}" ]]; then
    git fetch origin "$GITHUB_BASE_REF" --depth=1 2>/dev/null || true
    MERGE_BASE="$(git merge-base "origin/$GITHUB_BASE_REF" HEAD 2>/dev/null)" \
        || MERGE_BASE=""
    if [[ -z "$MERGE_BASE" ]]; then
        echo "Error: Could not find merge base for" \
            "$GITHUB_BASE_REF and HEAD." >&2
        exit 1
    fi
    HEAD_SHA="$(git rev-parse HEAD)"
elif [[ -z "$BASE_REF" ]] && [[ -z "$HEAD_REF" ]]; then
    if git rev-parse origin/main >/dev/null 2>&1; then
        MERGE_BASE="$(git merge-base origin/main HEAD)"
        HEAD_SHA="$(git rev-parse HEAD)"
    elif git rev-parse main >/dev/null 2>&1; then
        MERGE_BASE="$(git merge-base main HEAD)"
        HEAD_SHA="$(git rev-parse HEAD)"
    else
        echo "Error: No base ref. Pass base and head," \
            "or run from GitHub Actions." >&2
        exit 1
    fi
else
    echo "Error: Pass both base and head, or neither." >&2
    exit 1
fi

sig_diagnostic() {
    local sha="$1"
    local status="$2"
    local short
    short="$(git log -1 --oneline "$sha")"

    case "$status" in
        N)
            echo "Commit $sha has no signature." >&2
            ;;
        B)
            echo "Commit $sha has a BAD signature." \
                "Re-sign with a valid key." >&2
            ;;
        E)
            echo "Commit $sha signature cannot be verified" \
                "(signing key not in your keyring)." \
                "Import the key or re-sign." >&2
            ;;
        X)
            echo "Commit $sha signature is good but" \
                "EXPIRED." >&2
            ;;
        Y)
            echo "Commit $sha signature was made with" \
                "an EXPIRED key." >&2
            ;;
        R)
            echo "Commit $sha signature was made with" \
                "a REVOKED key." >&2
            ;;
        *)
            echo "Commit $sha has unexpected signature" \
                "status '$status'." >&2
            ;;
    esac
    echo "  $short" >&2
}

FAILED=0
while read -r sha; do
    if [[ -z "$sha" ]]; then
        continue
    fi
    status="$(git log -1 --format='%G?' "$sha")"

    if [[ "$PRESENCE_ONLY" -eq 1 ]]; then
        if [[ "$status" == "N" ]]; then
            sig_diagnostic "$sha" "$status"
            FAILED=1
        fi
    else
        if [[ "$status" != "G" ]] && [[ "$status" != "U" ]]; then
            sig_diagnostic "$sha" "$status"
            FAILED=1
        fi
    fi
done < <(git log --first-parent --format=%H \
    "$MERGE_BASE..$HEAD_SHA" 2>/dev/null || true)

if [[ "$FAILED" -eq 1 ]]; then
    echo "" >&2
    echo "All commits must be cryptographically signed" \
        "(GPG or SSH)." >&2
    echo "See CONTRIBUTING.md 'Commit signing setup'." >&2
    if [[ "$PRESENCE_ONLY" -eq 0 ]]; then
        echo "Run: make check-signatures" >&2
    fi
    exit 1
fi

if [[ "$PRESENCE_ONLY" -eq 1 ]]; then
    echo "Signature presence check passed."
else
    echo "Signature check passed (strict)."
fi
