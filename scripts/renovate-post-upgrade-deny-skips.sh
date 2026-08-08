#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Sync deny.toml [bans.skip] version pins after Cargo dependency updates (Renovate
# postUpgradeTasks). Keeps cargo-deny skip entries aligned with Cargo.lock.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH (Python installTools missing?)" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not on PATH (Rust installTools missing?)" >&2
  exit 1
fi

python3 "${ROOT}/scripts/sync_deny_skips.py"

CARGO_DENY_VERSION="$(
  grep -E '^\s+CARGO_DENY_VERSION:' "${ROOT}/.github/workflows/ci.yml" \
    | sed -E 's/.*"([^"]+)".*/\1/' \
    | head -1
)"
if [[ -z "${CARGO_DENY_VERSION}" ]]; then
  echo "ERROR: could not read CARGO_DENY_VERSION from .github/workflows/ci.yml" >&2
  exit 1
fi
if ! command -v cargo-deny >/dev/null 2>&1 \
  || ! cargo-deny --version 2>/dev/null | grep -Fq "cargo-deny ${CARGO_DENY_VERSION}"; then
  cargo install cargo-deny --locked --version "${CARGO_DENY_VERSION}"
fi

if ! command -v make >/dev/null 2>&1; then
  echo "ERROR: make not on PATH (required for deny-check)" >&2
  exit 1
fi

make -C "${ROOT}" -f "${ROOT}/Makefile" deny-check
