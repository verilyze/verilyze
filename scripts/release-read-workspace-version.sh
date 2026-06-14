#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Print [workspace.package].version from the root Cargo.toml.
# Usage: release-read-workspace-version.sh [path/to/Cargo.toml]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cargo_toml="${script_dir}/../Cargo.toml"
if [[ $# -eq 1 ]]; then
  cargo_toml="$1"
  if [[ "${cargo_toml}" != /* ]]; then
    cargo_toml="$(cd "${script_dir}/.." && pwd)/${cargo_toml}"
  fi
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

printf '%s\n' "${workspace_version}"
