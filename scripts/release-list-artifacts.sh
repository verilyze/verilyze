#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# List publishable release artifacts in deterministic order (flat basenames).
# Usage: release-list-artifacts.sh <dir> [--include-sha256sums]
#
# <dir> is typically the github-upload staging directory containing archives,
# .deb, .rpm, and optional SHA256SUMS.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-artifact-names.sh
source "${script_dir}/lib/release-artifact-names.sh"

readonly SHA256SUMS_FILE="SHA256SUMS"

usage() {
  echo "usage: $0 <artifact-dir> [--include-sha256sums]" >&2
  exit 2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

artifacts_dir="$1"
include_sha256sums=0
if [[ $# -eq 2 ]]; then
  if [[ "$2" != "--include-sha256sums" ]]; then
    usage
  fi
  include_sha256sums=1
fi

if [[ ! -d "${artifacts_dir}" ]]; then
  echo "error: release artifacts directory does not exist: ${artifacts_dir}" >&2
  exit 1
fi

root_abs="$(cd "${artifacts_dir}" && pwd)"
tmp_list="$(mktemp)"
trap 'rm -f "${tmp_list}"' EXIT

(
  cd "${root_abs}"
  shopt -s nullglob
  for platform in "${RELEASE_PLATFORMS[@]}"; do
    ext="$(release_archive_extension "${platform}")"
    while IFS= read -r -d '' f; do
      printf '%s\n' "${f#./}"
    done < <(find . -maxdepth 1 -type f -name "vlz-*-${platform}.${ext}" -print0)
  done
  while IFS= read -r -d '' f; do
    printf '%s\n' "${f#./}"
  done < <(find . -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -print0)
  if [[ "${include_sha256sums}" -eq 1 && -f "${SHA256SUMS_FILE}" ]]; then
    printf '%s\n' "${SHA256SUMS_FILE}"
  fi
) | LC_ALL=C sort -u > "${tmp_list}"

if [[ ! -s "${tmp_list}" ]]; then
  echo "error: no release artifacts found under ${root_abs}" >&2
  exit 1
fi

cat "${tmp_list}"
