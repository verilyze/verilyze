#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Refresh .cursor/Dockerfile rustup-init SHA-256 ARGs after Renovate bumps
# ARG RUSTUP_VERSION (postUpgradeTasks). Keeps checksums aligned with
# https://static.rust-lang.org/rustup/archive/<ver>/<triple>/rustup-init.sha256.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH" >&2
  exit 1
fi

PYTHONPATH="${ROOT}" python3 "${ROOT}/scripts/rustup_init_pins.py"
