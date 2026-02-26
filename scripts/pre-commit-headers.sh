#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Pre-commit hook logic: add REUSE headers to newly added files using the
# author as copyright holder. Invoked by .git/hooks/pre-commit when
# installed via scripts/install-hooks.sh.
#
# For newly added files (git diff --cached --diff-filter=A) that need headers,
# runs: reuse annotate -c "Name <email>" -y YEAR -l GPL-3.0-or-later
#
# Run from repository root: ./scripts/pre-commit-headers.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Load config from pyproject.toml via update_headers.py (no eval)
DEFAULT_LICENSE="GPL-3.0-or-later"
DEFAULT_COPYRIGHT="The verilyze contributors"
EXTENSIONS="rs toml md mmd sh json"
LITERAL_NAMES="Makefile"
EXCLUDE_PATHS="tools/xtask Cargo.lock"
while IFS=: read -r key value; do
    case "$key" in
        license) DEFAULT_LICENSE="$value" ;;
        copyright) DEFAULT_COPYRIGHT="$value" ;;
        extensions) EXTENSIONS="$value" ;;
        literal_names) LITERAL_NAMES="$value" ;;
        exclude_paths) EXCLUDE_PATHS="$value" ;;
    esac
done < <(python3 scripts/update_headers.py --print-config 2>/dev/null || true)
REUSE_CMD="$REPO_ROOT/scripts/ensure-reuse.sh"

# Ensure LICENSES exists
if ! [ -d "LICENSES" ]; then
    $REUSE_CMD download "$DEFAULT_LICENSE" >/dev/null 2>&1 || true
fi

# Determine author for copyright (matches Git's precedence: env vars > config)
if [ -n "${GIT_AUTHOR_NAME:-}" ] && [ -n "${GIT_AUTHOR_EMAIL:-}" ]; then
    copyright="${GIT_AUTHOR_NAME} <${GIT_AUTHOR_EMAIL}>"
else
    user_name=$(git config user.name 2>/dev/null || true)
    user_email=$(git config user.email 2>/dev/null || true)
    if [ -n "$user_name" ] && [ -n "$user_email" ]; then
        copyright="$user_name <$user_email>"
    elif [ -n "$DEFAULT_COPYRIGHT" ]; then
        copyright="$DEFAULT_COPYRIGHT"
    else
        echo "REUSE pre-commit: GIT_AUTHOR_NAME/GIT_AUTHOR_EMAIL or git user.name/user.email required for copyright headers." >&2
        echo "  Configure: git config user.name 'Your Name' && git config user.email 'you@example.com'" >&2
        exit 1
    fi
fi
year=$(date +%Y)

# Check if file matches covered patterns and is not excluded
is_covered() {
    local f="$1"
    local base
    for ex in $EXCLUDE_PATHS; do
        case "$f" in
            "$ex"|"$ex"/*) return 1 ;;
        esac
    done
    for ext in $EXTENSIONS; do
        case "$f" in
            *.$ext) return 0 ;;
        esac
    done
    base=$(basename "$f")
    for lit in $LITERAL_NAMES; do
        if [ "$base" = "$lit" ]; then
            return 0
        fi
    done
    return 1
}

# Check if file lacks SPDX headers (returns 0 when headers are missing)
needs_headers() {
    local f="$1"
    [ -f "$f" ] || return 1
    ! head -30 "$f" 2>/dev/null | grep -qE "SPDX-FileCopyrightText|SPDX-License-Identifier"
}

annotated=0
while IFS= read -r file; do
    [ -z "$file" ] && continue
    is_covered "$file" || continue
    needs_headers "$file" || continue

    if $REUSE_CMD annotate -c "$copyright" -y "$year" -l "$DEFAULT_LICENSE" \
        --merge-copyrights "$file" 2>/dev/null; then
        :
    else
        $REUSE_CMD annotate -c "$copyright" -y "$year" -l "$DEFAULT_LICENSE" \
            --merge-copyrights --force-dot-license "$file" 2>/dev/null || continue
    fi
    git add "$file"
    annotated=$((annotated + 1))
done < <(git diff --cached --diff-filter=A --name-only 2>/dev/null)

if [ "$annotated" -gt 0 ]; then
    echo "REUSE: added headers (author: $copyright) to $annotated new file(s)."
fi
exit 0
