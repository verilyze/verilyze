#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Copy cross-platform binaries into flat GitHub Release asset names.
# softprops/action-gh-release uploads basenames as-is and does not support
# path#name rename syntax.
# Usage: release-stage-github-binary-upload.sh <release-artifacts-dir> [upload-subdir]

set -euo pipefail

readonly STAGED_BINARIES=(
  "vlz-linux-x86_64/vlz|vlz-linux-x86_64"
  "vlz-macos-aarch64/vlz|vlz-macos-aarch64"
  "vlz-windows-x86_64/vlz.exe|vlz-windows-x86_64.exe"
)
readonly DEFAULT_UPLOAD_SUBDIR="github-upload"

usage() {
  echo "usage: $0 <release-artifacts-dir> [upload-subdir]" >&2
  exit 2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

artifacts_dir="$1"
upload_subdir="${2:-${DEFAULT_UPLOAD_SUBDIR}}"

if [[ ! -d "${artifacts_dir}" ]]; then
  echo "error: release artifacts directory does not exist: ${artifacts_dir}" >&2
  exit 1
fi

upload_dir="${artifacts_dir}/${upload_subdir}"
mkdir -p "${upload_dir}"

for entry in "${STAGED_BINARIES[@]}"; do
  rel_path="${entry%%|*}"
  asset_name="${entry#*|}"
  src="${artifacts_dir}/${rel_path}"
  if [[ ! -f "${src}" ]]; then
    echo "error: missing release artifact: ${rel_path}" >&2
    exit 1
  fi
  cp -f "${src}" "${upload_dir}/${asset_name}"
  for suffix in .sigstore.json .intoto.jsonl; do
    if [[ -f "${src}${suffix}" ]]; then
      cp -f "${src}${suffix}" "${upload_dir}/${asset_name}${suffix}"
    fi
  done
done

echo "Staged flat binary upload assets under ${upload_dir}"
