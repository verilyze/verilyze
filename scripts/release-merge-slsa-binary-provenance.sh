#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Copy SLSA generator provenance bundles next to platform release archives.
# Usage: release-merge-slsa-binary-provenance.sh <release-artifacts-dir> <version>

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-artifact-names.sh
source "${script_dir}/lib/release-artifact-names.sh"

usage() {
  echo "usage: $0 <release-artifacts-dir> <version>" >&2
  exit 2
}

if [[ $# -ne 2 ]]; then
  usage
fi

root="$1"
version="$2"
if [[ ! -d "${root}" ]]; then
  echo "error: release artifacts directory does not exist: ${root}" >&2
  exit 1
fi

for platform in "${RELEASE_PLATFORMS[@]}"; do
  actions_name="$(release_actions_artifact_name "${platform}")"
  archive_name="$(release_archive_basename "${version}" "${platform}")"
  slsa_name="$(release_slsa_provenance_basename "${platform}")"
  slsa_src="$(find "${root}" -name "${slsa_name}" -type f | head -n 1 || true)"
  archive_path="${root}/${actions_name}/${archive_name}"
  if [[ ! -f "${archive_path}" ]]; then
    echo "error: missing archive artifact: ${archive_path}" >&2
    exit 1
  fi
  if [[ -z "${slsa_src}" || ! -f "${slsa_src}" ]]; then
    echo "error: missing SLSA provenance bundle: ${slsa_name}" >&2
    exit 1
  fi
  cp "${slsa_src}" "${archive_path}.intoto.jsonl"
done

echo "Merged SLSA archive provenance bundles into release-artifacts layout"
