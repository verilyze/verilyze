#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Resolve which AFL fuzz targets to run (shared by fuzz.sh and CI preflight).
#
# Usage:
#   source scripts/lib/fuzz-resolve-targets.sh
#   fuzz_resolve_targets changed   # stdout: comma list or empty; stderr: reason
#   fuzz_resolve_targets all
#   fuzz_resolve_targets targets config_toml,requirements_txt
#
# Exit 0 always; empty stdout means skip (no targets).

set -euo pipefail

_fuzz_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_fuzz_repo_root="$(cd "${_fuzz_lib_dir}/../.." && pwd)"

FUZZ_TARGETS_FILE="${FUZZ_TARGETS_FILE:-${_fuzz_lib_dir}/../fuzz-targets.map}"

# Shared crates: any change triggers all targets (must match fuzz.sh).
FUZZ_SHARED_PATH_PATTERNS=(
    "crates/core/vlz-db/"
    "crates/db-backends/vlz-db-redb/"
    "crates/core/vlz-plugin-macro/"
)

fuzz_get_all_targets() {
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line// }"
        [[ -z "$line" ]] && continue
        if [[ "$line" == *=* ]]; then
            echo "${line%%=*}"
        fi
    done < "$FUZZ_TARGETS_FILE"
}

fuzz_merge_base_ref() {
    local base_ref=""
    local ref
    if ref=$(git -C "$_fuzz_repo_root" rev-parse --abbrev-ref 'HEAD@{upstream}' 2>/dev/null); then
        base_ref=$(git -C "$_fuzz_repo_root" merge-base HEAD "origin/$ref" 2>/dev/null || true)
    fi
    [[ -z "$base_ref" ]] && base_ref=$(git -C "$_fuzz_repo_root" merge-base HEAD origin/main 2>/dev/null || true)
    [[ -z "$base_ref" ]] && base_ref=$(git -C "$_fuzz_repo_root" merge-base HEAD main 2>/dev/null || true)
    [[ -z "$base_ref" ]] && base_ref="main"
    printf '%s' "$base_ref"
}

fuzz_changed_files() {
    local base_ref="$1"
    if [[ -n "$base_ref" ]] && git -C "$_fuzz_repo_root" rev-parse --verify "$base_ref" >/dev/null 2>&1; then
        git -C "$_fuzz_repo_root" diff --name-only "$base_ref"..HEAD 2>/dev/null || true
        return 0
    fi
    printf ''
}

# Release prep touches these paths only; do not run the full AFL matrix for
# workspace version bumps (Cargo.toml / Cargo.lock) on pull requests.
fuzz_is_release_only_change() {
    local f
    for f in $1; do
        case "$f" in
            CHANGELOG.md | Cargo.toml | Cargo.lock) ;;
            packaging/* | sbom/*) ;;
            scripts/lib/fuzz-resolve-targets.sh) ;;
            scripts/coverage.sh) ;;
            tests/scripts/test_fuzz_resolve_targets.py) ;;
            Makefile) ;;
            tests/scripts/test_makefile_fuzz_then_coverage.py) ;;
            tests/scripts/test_makefile_check_includes_deny.py) ;;
            *) return 1 ;;
        esac
    done
    return 0
}

fuzz_targets_trigger_run_all() {
    local f pat
    if fuzz_is_release_only_change "$1"; then
        return 1
    fi
    for f in $1; do
        for pat in "${FUZZ_SHARED_PATH_PATTERNS[@]}"; do
            if [[ "$f" == "$pat"* ]]; then
                return 0
            fi
        done
        if [[ "$f" == tests/fuzz/* ]] || [[ "$f" == Cargo.toml ]] || [[ "$f" == Cargo.lock ]]; then
            return 0
        fi
    done
    return 1
}

fuzz_match_changed_to_targets() {
    local changed_files="$1"
    local matched="" line target path f
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line// }"
        [[ -z "$line" ]] || [[ "$line" != *=* ]] && continue
        target="${line%%=*}"
        path="${line#*=}"
        for f in $changed_files; do
            if [[ "$f" == "$path" ]] || [[ "$f" == "$path"* ]]; then
                matched="${matched:+$matched,}$target"
                break
            fi
        done
    done < "$FUZZ_TARGETS_FILE"
    printf '%s' "$matched"
}

fuzz_all_targets_csv() {
    local csv
    csv=$(fuzz_get_all_targets | tr '\n' ',')
    printf '%s' "${csv%,}"
}

# Resolve targets for --changed semantics. Prints CSV to stdout; logs reason on stderr.
fuzz_resolve_changed_targets() {
    local base_ref changed_files matched
    base_ref=$(fuzz_merge_base_ref)
    changed_files=$(fuzz_changed_files "$base_ref")

    if [[ -z "$changed_files" ]] && [[ -z "$base_ref" ]]; then
        echo "Running all fuzz targets (change detection inconclusive)." >&2
        fuzz_all_targets_csv
        return 0
    fi

    if [[ -n "$changed_files" ]]; then
        if fuzz_targets_trigger_run_all "$changed_files"; then
            echo "Running all fuzz targets (shared/fuzz/crate changes)." >&2
            fuzz_all_targets_csv
            return 0
        fi
        matched=$(fuzz_match_changed_to_targets "$changed_files")
        if [[ -z "$matched" ]]; then
            echo "No mapped files changed; skipping fuzz (exit 0)." >&2
            return 0
        fi
        echo "Running fuzz targets for changed code: $matched" >&2
        printf '%s' "$matched"
        return 0
    fi

    echo "No mapped files changed; skipping fuzz (exit 0)." >&2
}

fuzz_resolve_targets() {
    local mode="${1:-}"
    shift || true
    case "$mode" in
        changed)
            fuzz_resolve_changed_targets
            ;;
        all)
            fuzz_all_targets_csv
            ;;
        targets)
            local filter="${1:-}"
            filter="${filter// }"
            printf '%s' "$filter"
            ;;
        *)
            echo "fuzz_resolve_targets: unknown mode '$mode'" >&2
            return 2
            ;;
    esac
}

# CLI entry when executed directly (CI preflight: --changed --dry-run).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _cli_mode=""
    _cli_dry_run=false
    for arg in "$@"; do
        case "$arg" in
            --changed) _cli_mode=changed ;;
            --all) _cli_mode=all ;;
            --targets=*) _cli_mode=targets; _cli_filter="${arg#--targets=}" ;;
            --dry-run) _cli_dry_run=true ;;
        esac
    done
    [[ -n "$_cli_mode" ]] || {
        echo "usage: fuzz-resolve-targets.sh --changed|--all [--dry-run]" >&2
        echo "       fuzz-resolve-targets.sh --targets=name,name [--dry-run]" >&2
        exit 2
    }
    if [[ "$_cli_mode" == targets ]]; then
        _resolved=$(fuzz_resolve_targets targets "$_cli_filter")
    else
        _resolved=$(fuzz_resolve_targets "$_cli_mode")
    fi
    if [[ -z "$_resolved" ]]; then
        if "$_cli_dry_run"; then
            echo "SKIP"
        fi
        exit 0
    fi
    if "$_cli_dry_run"; then
        echo "RUN:${_resolved}"
    else
        echo "$_resolved"
    fi
    exit 0
fi
