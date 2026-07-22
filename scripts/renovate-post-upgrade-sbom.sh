#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Regenerate committed workspace SBOM after pyproject.toml dev dep updates
# (Renovate pep621 postUpgradeTasks). Same output as make generate-sbom (SEC-019).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not on PATH (Rust installTools missing?)" >&2
  exit 1
fi

if ! command -v make >/dev/null 2>&1; then
  echo "ERROR: make not on PATH (required for generate-sbom)" >&2
  exit 1
fi

make -C "${ROOT}" -f "${ROOT}/Makefile" generate-pylock-dev
make -C "${ROOT}" -f "${ROOT}/Makefile" generate-sbom
