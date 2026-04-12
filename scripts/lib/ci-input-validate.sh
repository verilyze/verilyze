# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Allow-list validation for inputs fed from GitHub Actions (OP-019).
# Sourced by scripts in scripts/; do not execute standalone.
#
# SemVer subset aligned with Cargo [workspace.package].version and SemVer 2.0
# numeric identifiers (no leading zeros in each numeric part). Optional
# pre-release (-identifier) and build (+identifier) use conservative character
# classes for linear-time Bash [[ =~ ]] matching.
#
# shellcheck shell=bash

# Regex for release version strings (unquoted on right-hand side of [[ =~ ]]).
readonly VLZ_RELEASE_SEMVER_REGEX='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$'

vlz_is_merge_group_ci() {
  [[ "${GITHUB_EVENT_NAME:-}" == "merge_group" ]]
}

# Trim ASCII whitespace (space, tab, CR, LF) from both ends.
vlz_trim_ascii_ws() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

vlz_normalize_merge_group_sha_arg() {
  local raw
  raw=$(vlz_trim_ascii_ws "$1")
  printf '%s' "${raw,,}"
}

vlz_is_sha40_lc_hex() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

# When GITHUB_EVENT_NAME is merge_group, require two full SHA-1 object names
# (40 lowercase hex digits after trim and lower-case). On success sets
# VLZ_MERGE_SHA_BASE and VLZ_MERGE_SHA_HEAD for the caller to substitute.
# Returns 0 when not in merge_group CI (no globals set). Returns 1 on reject.
vlz_require_sha40_pair_if_merge_group() {
  unset VLZ_MERGE_SHA_BASE 2>/dev/null || true
  unset VLZ_MERGE_SHA_HEAD 2>/dev/null || true
  if ! vlz_is_merge_group_ci; then
    return 0
  fi
  local a b
  a=$(vlz_normalize_merge_group_sha_arg "$1")
  b=$(vlz_normalize_merge_group_sha_arg "$2")
  if ! vlz_is_sha40_lc_hex "$a" || ! vlz_is_sha40_lc_hex "$b"; then
    echo "Error: merge queue runs require two full 40-character lowercase" \
      "hexadecimal SHA-1 values for base and head (after trim and lower-case)." >&2
    return 1
  fi
  # Set for callers that source this file (not used within this file).
  # shellcheck disable=SC2034
  VLZ_MERGE_SHA_BASE=$a
  # shellcheck disable=SC2034
  VLZ_MERGE_SHA_HEAD=$b
  return 0
}

# Validate a release version string (already trimmed by caller if desired).
# Returns 0 if valid, 2 if invalid (exit 2 for CLI usage errors).
vlz_require_release_semver() {
  local v=$1
  if [[ ! "$v" =~ $VLZ_RELEASE_SEMVER_REGEX ]]; then
    echo "error: version must be SemVer (Cargo-style), without a leading v" \
      "prefix (got invalid value)." >&2
    return 2
  fi
  return 0
}
