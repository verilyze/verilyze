#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Regenerate THIRD-PARTY-LICENSES after Cargo dependency updates (Renovate
# postUpgradeTasks). Calls scripts/generate-third-party-licenses.sh (same as
# make generate-third-party-licenses).
#
# cargo-about: that script expects cargo-about on PATH; install a version
# aligned with .github/workflows/ci.yml (taiki-e/install-action tool line) when
# absent.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not on PATH (Rust installTools missing?)" >&2
  exit 1
fi

# Pinned to match CI install-action list in .github/workflows/ci.yml.
CARGO_ABOUT_VERSION="0.8.4"
if ! command -v cargo-about >/dev/null 2>&1; then
  cargo install cargo-about --locked --version "${CARGO_ABOUT_VERSION}"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH (Python installTools missing?)" >&2
  exit 1
fi

bash "${ROOT}/scripts/generate-third-party-licenses.sh"
