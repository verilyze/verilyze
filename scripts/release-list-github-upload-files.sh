#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# List every file to upload to GitHub Releases (explicit paths, no globs).
# Reads ARTIFACTS.list in the upload directory and prints workspace-relative
# paths for each listed asset plus its Sigstore bundles.
# Usage: release-list-github-upload-files.sh <upload-dir>

set -euo pipefail

usage() {
  echo "usage: $0 <upload-dir>" >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

upload_dir="$1"
if [[ ! -d "${upload_dir}" ]]; then
  echo "error: upload directory does not exist: ${upload_dir}" >&2
  exit 1
fi

list_file="${upload_dir}/ARTIFACTS.list"
if [[ ! -f "${list_file}" ]] || [[ ! -s "${list_file}" ]]; then
  echo "error: missing or empty ARTIFACTS.list under ${upload_dir}" >&2
  exit 1
fi

upload_dir="${upload_dir%/}"

while IFS= read -r basename; do
  [[ -z "${basename}" ]] && continue
  printf '%s/%s\n' "${upload_dir}" "${basename}"
  printf '%s/%s.sigstore.json\n' "${upload_dir}" "${basename}"
  printf '%s/%s.intoto.jsonl\n' "${upload_dir}" "${basename}"
done < "${list_file}"
