#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Refresh .cursor/Dockerfile Flutter / Dart pin ARGs after Renovate bumps
# ARG FLUTTER_VERSION (postUpgradeTasks). Keeps checksums aligned with
# flutter_infra_release releases_linux.json and dart-archive arm64 sums.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not on PATH" >&2
  exit 1
fi

PYTHONPATH="${ROOT}" python3 "${ROOT}/scripts/flutter_sdk_pins.py"
