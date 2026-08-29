#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Validate crates.io packaging (manifests, assets, cargo package / publish --dry-run).
# Usage: check-crates-publish.sh [--manifest-only]

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
cd "${root}"

args=(--check)
if [[ "${1:-}" == "--manifest-only" ]]; then
  args+=(--manifest-only)
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--manifest-only]" >&2
  exit 2
fi

./scripts/sync-vlz-crate-assets.sh --check
PYTHONPATH="${root}" python3 "${script_dir}/crates_publish.py" "${args[@]}"
