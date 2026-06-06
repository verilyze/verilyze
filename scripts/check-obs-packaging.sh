#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBS_ENV="${ROOT_DIR}/packaging/obs/obs-project.env"
DEBIAN_CONTROL="${ROOT_DIR}/packaging/obs/debian/debian/control"
VLZ_CARGO="${ROOT_DIR}/crates/core/vlz/Cargo.toml"
OBS_SERVICE="${ROOT_DIR}/packaging/obs/_service"
OBS_SPEC="${ROOT_DIR}/packaging/obs/rpm/verilyze.spec"

if [[ ! -f "${OBS_ENV}" ]]; then
  echo "ERROR: missing OBS coordinate file: ${OBS_ENV}" >&2
  exit 1
fi

# Use grep (not ripgrep) so CI runners without `rg` still pass (NFR-021).
if ! grep -qE '^OBS_PROJECT=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_PROJECT must be set in ${OBS_ENV}" >&2
  exit 1
fi

if ! grep -qE '^OBS_PACKAGE=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_PACKAGE must be set in ${OBS_ENV}" >&2
  exit 1
fi

if [[ ! -f "${DEBIAN_CONTROL}" ]]; then
  echo "ERROR: missing Debian control file: ${DEBIAN_CONTROL}" >&2
  exit 1
fi

if ! grep -qE '^Package:[[:space:]]+verilyze$' "${DEBIAN_CONTROL}"; then
  echo "ERROR: Debian package name must remain verilyze." >&2
  exit 1
fi

if [[ ! -f "${VLZ_CARGO}" ]]; then
  echo "ERROR: missing Cargo manifest: ${VLZ_CARGO}" >&2
  exit 1
fi

if ! grep -qE '^\[package\.metadata\.deb\]$' "${VLZ_CARGO}"; then
  echo "ERROR: cargo-deb metadata block is required in ${VLZ_CARGO}" >&2
  exit 1
fi

if [[ ! -f "${OBS_SERVICE}" ]]; then
  echo "ERROR: missing OBS source service file: ${OBS_SERVICE}" >&2
  exit 1
fi

if [[ ! -f "${OBS_SPEC}" ]]; then
  echo "ERROR: missing OBS RPM spec: ${OBS_SPEC}" >&2
  exit 1
fi

if ! grep -q -- '--offline' "${OBS_SPEC}"; then
  echo "ERROR: ${OBS_SPEC} must build cargo with --offline" >&2
  exit 1
fi

if ! grep -q 'vendor.tar.zst' "${OBS_SPEC}"; then
  echo "ERROR: ${OBS_SPEC} must declare vendor.tar.zst as Source1" >&2
  exit 1
fi

UPLOAD_SCRIPT="${ROOT_DIR}/scripts/obs-upload-release-sources.sh"
if [[ ! -x "${UPLOAD_SCRIPT}" ]]; then
  echo "ERROR: missing OBS upload script: ${UPLOAD_SCRIPT}" >&2
  exit 1
fi

RELEASE_WORKFLOW="${ROOT_DIR}/.github/workflows/release.yml"
if ! grep -q 'obs-upload-release-sources.sh' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must invoke obs-upload-release-sources.sh" >&2
  exit 1
fi
if ! grep -q -- '--skip-runservice' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must trigger OBS rebuild with --skip-runservice" >&2
  exit 1
fi

"${ROOT_DIR}/scripts/check-obs-signing.sh" \
  --config "${OBS_ENV}"
