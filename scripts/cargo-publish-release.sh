#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Publish workspace crates to crates.io in dependency order (tagged releases only).
# Usage: cargo-publish-release.sh
#
# Requires CARGO_REGISTRY_TOKEN (secret or OIDC via crates-io-auth-action).
# Skips crates whose version is already on the registry (idempotent retries).

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
cd "${root}"

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  echo "error: CARGO_REGISTRY_TOKEN is required for cargo publish" >&2
  exit 1
fi

PYTHONPATH="${root}" python3 "${script_dir}/crates_publish.py" --publish
