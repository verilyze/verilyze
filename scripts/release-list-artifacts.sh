#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# List release artifacts in deterministic order.
# Usage: release-list-artifacts.sh <release-artifacts-dir> [--include-sha256sums]

set -euo pipefail

readonly ARTIFACT_PATTERNS=(
  "vlz-linux-x86_64/vlz"
  "deb-package/*.deb"
  "rpm-package/**/*.rpm"
)
readonly SHA256SUMS_FILE="SHA256SUMS"

usage() {
  echo "usage: $0 <release-artifacts-dir> [--include-sha256sums]" >&2
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
shopt -s nullglob globstar

(
  cd "${root_abs}"
  for pattern in "${ARTIFACT_PATTERNS[@]}"; do
    compgen -G "${pattern}" || true
  done
  if [[ "${include_sha256sums}" -eq 1 && -f "${SHA256SUMS_FILE}" ]]; then
    echo "${SHA256SUMS_FILE}"
  fi
) | LC_ALL=C sort -u > "${tmp_list}"

if [[ ! -s "${tmp_list}" ]]; then
  echo "error: no release artifacts found under ${root_abs}" >&2
  exit 1
fi

cat "${tmp_list}"
