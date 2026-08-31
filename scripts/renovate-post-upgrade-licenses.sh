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
CARGO_ABOUT_VERSION="$(
  grep -oE 'cargo-about@[0-9]+\.[0-9]+\.[0-9]+' \
    "${ROOT}/.github/workflows/ci.yml" \
    | head -1 \
    | cut -d@ -f2
)"
if [[ -z "${CARGO_ABOUT_VERSION}" ]]; then
  echo "ERROR: could not read cargo-about pin from .github/workflows/ci.yml" >&2
  exit 1
fi
if ! command -v cargo-about >/dev/null 2>&1 \
  || ! cargo-about --version 2>/dev/null | grep -Fq "${CARGO_ABOUT_VERSION}"; then
  cargo install cargo-about --locked --version "${CARGO_ABOUT_VERSION}" --features cli
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH (Python installTools missing?)" >&2
  exit 1
fi

bash "${ROOT}/scripts/generate-third-party-licenses.sh"

# SEC-019: refresh committed workspace SBOM (Cargo and pep621 post-upgrade hooks).
if [[ -f "${ROOT}/Cargo.lock" ]]; then
  if ! command -v make >/dev/null 2>&1; then
    echo "ERROR: make not on PATH (required for generate-sbom)" >&2
    exit 1
  fi
  make -C "${ROOT}" -f "${ROOT}/Makefile" generate-sbom
fi
