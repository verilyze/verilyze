#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Verify a release vlz binary meets the minimum version for SARIF upload (SEC-015).
#
# Usage: ci-verify-vlz-release-version.sh <vlz-binary> [min-version]
# Default min-version: 0.5.0 (Tier 1 declaration spans + Tier 2 evidence).

set -euo pipefail

: "${1:?vlz binary path is required}"
VLZ_BIN="$1"
MIN_VERSION="${2:-0.5.0}"

if [[ ! -x "${VLZ_BIN}" ]]; then
  echo "::error::VLZ_BIN is not executable: ${VLZ_BIN}" >&2
  exit 1
fi

version_line="$("${VLZ_BIN}" --version)"
if [[ "${version_line}" != vlz\ * ]]; then
  echo "::error::unexpected --version output: ${version_line}" >&2
  exit 1
fi

installed_version="${version_line#vlz }"
if ! python3 - "${installed_version}" "${MIN_VERSION}" <<'PY'
import sys

installed = tuple(int(part) for part in sys.argv[1].split("."))
minimum = tuple(int(part) for part in sys.argv[2].split("."))
width = max(len(installed), len(minimum))
installed = installed + (0,) * (width - len(installed))
minimum = minimum + (0,) * (width - len(minimum))
sys.exit(0 if installed >= minimum else 1)
PY
then
  echo "::error::installed vlz ${installed_version} is older than required ${MIN_VERSION}" >&2
  exit 1
fi

echo "::notice::verified vlz release version ${installed_version} (min ${MIN_VERSION})"
