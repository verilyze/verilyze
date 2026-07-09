#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Copy SLSA generator provenance bundles next to release binary artifacts.
# Usage: release-merge-slsa-binary-provenance.sh <release-artifacts-dir>

set -euo pipefail

usage() {
  echo "usage: $0 <release-artifacts-dir>" >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

root="$1"
if [[ ! -d "${root}" ]]; then
  echo "error: release artifacts directory does not exist: ${root}" >&2
  exit 1
fi

declare -A BINARY_FILES=(
  ["vlz-linux-x86_64"]="vlz"
  ["vlz-macos-aarch64"]="vlz"
  ["vlz-windows-x86_64"]="vlz.exe"
)

for artifact_name in "${!BINARY_FILES[@]}"; do
  binary_file="${BINARY_FILES[${artifact_name}]}"
  slsa_name="slsa-${artifact_name}.intoto.jsonl"
  slsa_src="$(find "${root}" -name "${slsa_name}" -type f | head -n 1 || true)"
  dest="${root}/${artifact_name}/${binary_file}.intoto.jsonl"
  if [[ -z "${slsa_src}" || ! -f "${slsa_src}" ]]; then
    echo "error: missing SLSA provenance bundle: ${slsa_name}" >&2
    exit 1
  fi
  if [[ ! -f "${root}/${artifact_name}/${binary_file}" ]]; then
    echo "error: missing binary artifact: ${root}/${artifact_name}/${binary_file}" >&2
    exit 1
  fi
  cp "${slsa_src}" "${dest}"
done

echo "Merged SLSA binary provenance bundles into release-artifacts layout"
