#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Regenerate THIRD-PARTY-LICENSES from deny.toml / about.toml and Cargo metadata.
# Single implementation used by the Makefile and scripts/renovate-post-upgrade-
# licenses.sh (Renovate). Run from any cwd (OP-017): resolves repo root from this
# file.
#
# Usage:
#   scripts/generate-third-party-licenses.sh
#   scripts/generate-third-party-licenses.sh --docker
#
# Requires: python3, cargo-about on PATH (see make setup / CI install-action).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

python3 "${ROOT}/scripts/sync_license_config.py"

if [[ "${1:-}" == "--docker" ]]; then
  cargo about generate -o THIRD-PARTY-LICENSES --fail \
    -c about.toml -m crates/core/vlz/Cargo.toml --no-default-features \
    --features docker about.hbs
else
  cargo about generate -o THIRD-PARTY-LICENSES --fail \
    -c about.toml -m crates/core/vlz/Cargo.toml about.hbs
fi
