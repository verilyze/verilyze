#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate an ephemeral benchmark fixture tree with many small manifests.
# Usage: scripts/generate-benchmark-fixture.sh DEST_DIR [MANIFEST_COUNT]

set -euo pipefail

DEST="${1:?destination directory required}"
COUNT="${2:-200}"

mkdir -p "${DEST}"

_i=1
while [[ "${_i}" -le "${COUNT}" ]]; do
  _dir="${DEST}/pkg${_i}"
  mkdir -p "${_dir}"
  printf 'benchdep%04d==1.0.0\n' "${_i}" > "${_dir}/requirements.txt"
  _i=$((_i + 1))
done

echo "Wrote ${COUNT} manifest directories under ${DEST}" >&2
