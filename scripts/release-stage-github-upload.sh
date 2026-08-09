#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Stage every publishable GitHub Release asset into a flat directory.
# softprops/action-gh-release uploads basenames as-is and does not support
# path#name rename syntax. SHA256SUMS is generated against this directory.
# Usage: release-stage-github-upload.sh <release-artifacts-dir> <version> [upload-subdir]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-artifact-names.sh
source "${script_dir}/lib/release-artifact-names.sh"

readonly DEFAULT_UPLOAD_SUBDIR="github-upload"

usage() {
  echo "usage: $0 <release-artifacts-dir> <version> [upload-subdir]" >&2
  exit 2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
fi

artifacts_dir="$1"
version="$2"
upload_subdir="${3:-${DEFAULT_UPLOAD_SUBDIR}}"

if [[ ! -d "${artifacts_dir}" ]]; then
  echo "error: release artifacts directory does not exist: ${artifacts_dir}" >&2
  exit 1
fi

artifacts_dir="$(cd "${artifacts_dir}" && pwd)"
upload_dir="${artifacts_dir}/${upload_subdir}"
rm -rf "${upload_dir}"
mkdir -p "${upload_dir}"

copy_with_sidecars() {
  local src="$1"
  local dest_name="$2"
  if [[ ! -f "${src}" ]]; then
    echo "error: missing release artifact: ${src}" >&2
    exit 1
  fi
  cp -f "${src}" "${upload_dir}/${dest_name}"
  for suffix in .sigstore.json .intoto.jsonl; do
    if [[ -f "${src}${suffix}" ]]; then
      cp -f "${src}${suffix}" "${upload_dir}/${dest_name}${suffix}"
    fi
  done
}

for platform in "${RELEASE_PLATFORMS[@]}"; do
  actions_name="$(release_actions_artifact_name "${platform}")"
  archive_name="$(release_archive_basename "${version}" "${platform}")"
  src="${artifacts_dir}/${actions_name}/${archive_name}"
  if [[ ! -f "${src}" ]]; then
    # Allow archives already at artifacts root (local round-trip fixtures).
    src="${artifacts_dir}/${archive_name}"
  fi
  copy_with_sidecars "${src}" "${archive_name}"
done

shopt -s nullglob globstar
for deb in "${artifacts_dir}"/deb-package/*.deb; do
  copy_with_sidecars "${deb}" "$(basename "${deb}")"
done

for rpm in "${artifacts_dir}"/rpm-package/**/*.rpm; do
  [[ -f "${rpm}" ]] || continue
  copy_with_sidecars "${rpm}" "$(basename "${rpm}")"
done
shopt -u nullglob globstar

echo "Staged flat GitHub upload assets under ${upload_dir}"
