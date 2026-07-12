# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Basename directory names skipped when scanning the verilyze workspace root
# (SEC-019 SBOM, SEC-015 dogfooding). Sourced by scripts/ci-verilyze-scan.sh
# and related tooling (NFR-024).
#
# shellcheck shell=bash

# shellcheck disable=SC2034  # array consumed by scripts that source this file
WORKSPACE_SCAN_EXCLUDE_DIRS=(
  target
  .venv-lint
  .venv-test
  .venv-reuse
)
