# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Basename directory names skipped when scanning the verilyze workspace root
# (SEC-019 SBOM, SEC-015 dogfooding). Sourced by scripts/ci-verilyze-scan.sh
# and related tooling (NFR-024).
#
# - sbom: committed CycloneDX/SPDX must not be re-ingested as FR-038 inventory
#   during dogfood/SBOM regenerate (sticky CVE loop). FR-038 SBOM-as-inventory
#   is covered by unit/integration tests and fixtures, not committed sbom/.
# - fuzz: cargo-fuzz tree is outside product SBOM / deny scope (CONTRIBUTING);
#   Trivy still scans fuzz/Cargo.lock. Basename match also skips tests/fuzz.
#
# shellcheck shell=bash

# shellcheck disable=SC2034  # array consumed by scripts that source this file
WORKSPACE_SCAN_EXCLUDE_DIRS=(
  .git
  target
  .venv-lint
  .venv-test
  .venv-reuse
  fixtures
  sbom
  fuzz
)
