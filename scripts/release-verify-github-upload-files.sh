#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Verify every path listed for GitHub Release upload exists as a non-empty file.
# Usage: release-verify-github-upload-files.sh <paths-file>
#   or:  release-list-github-upload-files.sh <dir> | release-verify-github-upload-files.sh -

set -euo pipefail

usage() {
  echo "usage: $0 <paths-file>" >&2
  echo "  paths-file may be - to read paths from stdin." >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

paths_file="$1"
if [[ "${paths_file}" == "-" ]]; then
  paths_file=/dev/stdin
elif [[ ! -f "${paths_file}" ]]; then
  echo "error: paths file does not exist: ${paths_file}" >&2
  exit 1
fi

while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  if [[ ! -f "${path}" ]]; then
    echo "error: upload path missing: ${path}" >&2
    exit 1
  fi
  if [[ ! -s "${path}" ]]; then
    echo "error: upload path empty: ${path}" >&2
    exit 1
  fi
done < "${paths_file}"
