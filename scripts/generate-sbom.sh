#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Regenerate workspace SBOM files (CycloneDX 1.6 + SPDX 3.0 JSON) via vlz scan.
# Single implementation used by the Makefile and Renovate post-upgrade hooks.
# Run from any cwd (OP-017): resolves repo root from this file.
#
# Usage:
#   scripts/generate-sbom.sh
#
# Environment:
#   VLZ_BIN  -- path to vlz binary (default: target/release/vlz, else target/debug/vlz)
#
# Requires: a built vlz binary (see make release or make debug).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# shellcheck source=lib/workspace-scan-excludes.sh
source "${ROOT}/scripts/lib/workspace-scan-excludes.sh"

SBOM_DIR="${ROOT}/sbom/v1"
CYCLONEDX_PATH="${SBOM_DIR}/verilyze.cdx.json"
SPDX_PATH="${SBOM_DIR}/verilyze.spdx.json"

# Directories skipped during workspace SBOM scan (basename match; see scan_exclude_dirs).
SBOM_SCAN_EXCLUDE_DIRS=("${WORKSPACE_SCAN_EXCLUDE_DIRS[@]}")

resolve_vlz_bin() {
  if [[ -n "${VLZ_BIN:-}" ]]; then
    if [[ ! -x "${VLZ_BIN}" ]]; then
      echo "ERROR: VLZ_BIN is not executable: ${VLZ_BIN}" >&2
      exit 1
    fi
    echo "${VLZ_BIN}"
    return
  fi
  local target_dir=""
  if command -v cargo >/dev/null 2>&1; then
    target_dir="$(
      cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['target_directory'])"
    )" || true
  fi
  if [[ -n "${target_dir}" && -x "${target_dir}/release/vlz" ]]; then
    echo "${target_dir}/release/vlz"
    return
  fi
  if [[ -x "${ROOT}/target/release/vlz" ]]; then
    echo "${ROOT}/target/release/vlz"
    return
  fi
  if [[ -n "${target_dir}" && -x "${target_dir}/debug/vlz" ]]; then
    echo "${target_dir}/debug/vlz"
    return
  fi
  if [[ -x "${ROOT}/target/debug/vlz" ]]; then
    echo "${ROOT}/target/debug/vlz"
    return
  fi
  echo "ERROR: vlz binary not found. Run: make release (or set VLZ_BIN)" >&2
  exit 1
}

VLZ="$(resolve_vlz_bin)"
mkdir -p "${SBOM_DIR}"

scan_args=(
  scan "${ROOT}"
  --offline --benchmark
)
for dir in "${SBOM_SCAN_EXCLUDE_DIRS[@]}"; do
  scan_args+=(--scan-exclude-dir "${dir}")
done
scan_args+=(
  --summary-file "cyclonedx:${CYCLONEDX_PATH}"
  --summary-file "spdx:${SPDX_PATH}"
)

# SEC-019: component inventory SBOM (deterministic; no network/CVE lookup).
# shellcheck source=lib/check-quiet-env.sh
source "${ROOT}/scripts/lib/check-quiet-env.sh"
vlz_apply_check_log_env
if vlz_check_verbose_enabled; then
  "${VLZ}" "${scan_args[@]}"
else
  "${VLZ}" "${scan_args[@]}" >/dev/null
fi

PYTHONPATH="${ROOT}" python3 "${ROOT}/scripts/normalize_sbom.py" \
  "${CYCLONEDX_PATH}" "${SPDX_PATH}"

if [[ ! -s "${CYCLONEDX_PATH}" ]]; then
  echo "ERROR: CycloneDX SBOM was not written: ${CYCLONEDX_PATH}" >&2
  exit 1
fi
if [[ ! -s "${SPDX_PATH}" ]]; then
  echo "ERROR: SPDX SBOM was not written: ${SPDX_PATH}" >&2
  exit 1
fi
