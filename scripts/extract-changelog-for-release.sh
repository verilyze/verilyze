#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Emit the CHANGELOG.md section for a single release version to stdout.
# Heading must match: ## [X.Y.Z] with optional " - date" or trailing text.
#
# Usage: extract-changelog-for-release.sh <semver-without-v-prefix> [path/to/CHANGELOG.md]
# Portable per OP-017: resolve repo root from script location, not cwd.

set -euo pipefail

usage() {
  echo "usage: $0 <semver-without-v-prefix> [CHANGELOG.md]" >&2
  exit 2
}

if [[ $# -lt 1 ]]; then
  usage
fi

version="$1"
rel_changelog="CHANGELOG.md"
if [[ $# -ge 2 ]]; then
  rel_changelog="$2"
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
changelog="${rel_changelog}"
if [[ "${changelog}" != /* ]]; then
  changelog="${root}/${rel_changelog}"
fi

if [[ ! -f "${changelog}" ]]; then
  echo "error: changelog not found: ${changelog}" >&2
  exit 1
fi

awk -v ver="${version}" '
/^## \[/ {
  if ($0 ~ "^## \\[" ver "\\]($| |-)") {
    if (found) {
      exit 0
    }
    found = 1
    print
    next
  }
  if (found) {
    exit 0
  }
  next
}
{
  if (found) {
    print
  }
}
END {
  if (!found) {
    exit 1
  }
}' "${changelog}"
