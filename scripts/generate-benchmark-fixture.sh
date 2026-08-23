#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate an ephemeral benchmark fixture tree with many small manifests.
# Usage: scripts/generate-benchmark-fixture.sh DEST_DIR [MANIFEST_COUNT]
# Status line on stderr only when VLZ_CHECK_VERBOSE=1 (or coverage verbose).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/check-quiet-env.sh
source "${SCRIPT_DIR}/lib/check-quiet-env.sh"

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

if vlz_check_verbose_enabled; then
  echo "Wrote ${COUNT} manifest directories under ${DEST}" >&2
fi
