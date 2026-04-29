#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate SHA256 checksum manifests for release artifacts.
# Usage: release-generate-checksums.sh <release-artifacts-dir>

set -euo pipefail

usage() {
  echo "usage: $0 <release-artifacts-dir>" >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

artifacts_dir="$1"
if [[ ! -d "${artifacts_dir}" ]]; then
  echo "error: release artifacts directory does not exist: ${artifacts_dir}" >&2
  exit 1
fi

root_abs="$(cd "${artifacts_dir}" && pwd)"
tmp_list="$(mktemp)"
trap 'rm -f "${tmp_list}"' EXIT
shopt -s nullglob globstar

# Keep deterministic ordering for reproducible manifests.
(
  cd "${root_abs}"
  for pattern in "vlz-linux-x86_64/vlz" "deb-package/*.deb" "rpm-package/**/*.rpm"; do
    compgen -G "${pattern}" || true
  done
) | LC_ALL=C sort -u > "${tmp_list}"

if [[ ! -s "${tmp_list}" ]]; then
  echo "error: no release artifacts found under ${root_abs}" >&2
  exit 1
fi

sha256_file="${root_abs}/SHA256SUMS"
: > "${sha256_file}"
while IFS= read -r rel_path; do
  (
    cd "${root_abs}"
    sha256sum "${rel_path}"
  ) >> "${sha256_file}"
done < "${tmp_list}"

printf '%s\n' "${sha256_file}"
