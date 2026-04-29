#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Validate that a release tag version matches workspace package version.
# Usage: release-verify-tag-version.sh <tag-or-ref> [path/to/Cargo.toml]

set -euo pipefail

usage() {
  echo "usage: $0 <tag-or-ref> [Cargo.toml]" >&2
  exit 2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/ci-input-validate.sh
. "${script_dir}/lib/ci-input-validate.sh"

tag_ref=$(vlz_trim_ascii_ws "$1")
if [[ -z "${tag_ref}" ]]; then
  echo "error: tag-or-ref must be non-empty." >&2
  exit 2
fi

if [[ "${tag_ref}" == refs/tags/* ]]; then
  tag_ref="${tag_ref#refs/tags/}"
fi

if [[ "${tag_ref}" != v* ]]; then
  echo "error: release tags must start with v (got: ${tag_ref})." >&2
  exit 2
fi
tag_version="${tag_ref#v}"

vlz_require_release_semver "${tag_version}"
_rc=$?
if [[ "${_rc}" -ne 0 ]]; then
  exit "${_rc}"
fi

cargo_toml="${script_dir}/../Cargo.toml"
if [[ $# -eq 2 ]]; then
  cargo_toml="$2"
fi
if [[ "${cargo_toml}" != /* ]]; then
  cargo_toml="$(cd "${script_dir}/.." && pwd)/${cargo_toml}"
fi

if [[ ! -f "${cargo_toml}" ]]; then
  echo "error: Cargo.toml not found: ${cargo_toml}" >&2
  exit 1
fi

workspace_version=$(
  awk '
    BEGIN { in_ws_pkg = 0 }
    /^\[workspace\.package\][[:space:]]*$/ { in_ws_pkg = 1; next }
    /^\[/ { in_ws_pkg = 0 }
    in_ws_pkg && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*/, "", line)
      gsub(/"/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      print line
      exit
    }
  ' "${cargo_toml}"
)

if [[ -z "${workspace_version}" ]]; then
  echo "error: could not read [workspace.package].version from ${cargo_toml}" >&2
  exit 1
fi

if [[ "${workspace_version}" != "${tag_version}" ]]; then
  echo "error: tag version ${tag_version} does not match workspace version ${workspace_version}." >&2
  exit 1
fi

printf '%s\n' "${tag_version}"
