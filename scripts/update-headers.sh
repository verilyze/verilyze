#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Add REUSE-compliant copyright and license headers to covered text files.
# Uses git history and the 15-line "nontrivial change" threshold (see docs/NONTRIVIAL-CHANGE.md).
#
# Run from repository root: ./scripts/update-headers.sh

set -e

NONTRIVIAL_LINES=15
DEFAULT_COPYRIGHT="The super-duper contributors"
DEFAULT_LICENSE="GPL-3.0-or-later"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# File patterns: extensions and literal names for covered files
EXTENSIONS="rs toml md mmd sh json"
LITERAL_NAMES="Makefile"

# Paths to exclude (handled by REUSE.toml or not source)
EXCLUDE_PATHS="tools/xtask Cargo.lock package-lock.json"

cd "$REPO_ROOT"

# Ensure reuse is available (see scripts/ensure-reuse.sh; never touches .venv)
REUSE_CMD="$REPO_ROOT/scripts/ensure-reuse.sh"

# Ensure LICENSES exists
if ! [ -d "LICENSES" ]; then
    echo "Downloading GPL-3.0-or-later..."
    $REUSE_CMD download GPL-3.0-or-later
fi

# Collect covered files (git-tracked, matching patterns, not excluded)
collect_files() {
    git ls-files | while read -r f; do
        # Exclude paths
        for ex in $EXCLUDE_PATHS; do
            case "$f" in
                "$ex"|"$ex"/*) continue 2 ;;
            esac
        done
        # Match extensions
        for ext in $EXTENSIONS; do
            case "$f" in
                *.$ext) echo "$f"; continue 2 ;;
            esac
        done
        # Match literal names
        base=$(basename "$f")
        for lit in $LITERAL_NAMES; do
            if [ "$base" = "$lit" ]; then
                echo "$f"
                continue 2
            fi
        done
    done
}

# Get nontrivial contributors for a file: outputs "YEAR Author <email>" per line (>= 15 lines)
get_nontrivial_authors() {
    local file="$1"
    git log --numstat --format="%aN <%aE>
%ad" --date=format:%Y --follow -- "$file" 2>/dev/null | awk -v threshold="$NONTRIVIAL_LINES" '
        /^[0-9]+\t/ {
            if (author != "") {
                add[author] += $1 + 0
                if (year != "") {
                    if (!(author in firstyear)) firstyear[author] = year
                    lastyear[author] = year
                }
            }
            next
        }
        /^[0-9]{4}$/ { year = $0; next }
        NF > 0 && !/^[0-9]/ { author = $0; year = ""; next }
        END {
            for (a in add) {
                if (add[a] >= threshold && a != "") {
                    fy = firstyear[a]
                    ly = lastyear[a]
                    if (fy == "" || ly == "") fy = ly = "?"
                    if (fy == ly) yrange = fy
                    else yrange = fy "-" ly
                    print yrange " " a
                }
            }
        }
    '
}

# Annotate one file with reuse
annotate_file() {
    local file="$1"
    shift
    local authors=("$@")

    local args=(-l "$DEFAULT_LICENSE" --merge-copyrights)
    if [ ${#authors[@]} -eq 0 ]; then
        # Fallback: use first commit author for files with history
        local first_author
        first_author=$(git log --reverse -1 --format="%ad %aN <%aE>" --date=format:%Y --follow -- "$file" 2>/dev/null)
        if [ -n "$first_author" ]; then
            authors=("$first_author")
        else
            args+=(-c "$DEFAULT_COPYRIGHT" -y "$(date +%Y)")
        fi
    fi
    if [ ${#authors[@]} -gt 0 ]; then
        for entry in "${authors[@]}"; do
            year="${entry%% *}"
            rest="${entry#* }"
            [ -z "$rest" ] && continue
            args+=(-c "$rest" -y "$year")
        done
    fi

    if $REUSE_CMD annotate "${args[@]}" "$file" 2>/dev/null; then
        :
    else
        $REUSE_CMD annotate "${args[@]}" --force-dot-license "$file" 2>/dev/null || true
    fi
}

# Main
updated=0
while read -r file; do
    [ -z "$file" ] && continue
    [ ! -f "$file" ] && continue

    case "$file" in
        Cargo.lock|package-lock.json) continue ;;
    esac

    authors=()
    while IFS= read -r line; do
        [ -n "$line" ] && authors+=("$line")
    done < <(get_nontrivial_authors "$file")

    annotate_file "$file" "${authors[@]}"
    updated=$((updated + 1))
    echo "Annotated: $file"
done < <(collect_files)

echo "Updated $updated file(s)."
