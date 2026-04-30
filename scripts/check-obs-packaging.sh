#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBS_ENV="${ROOT_DIR}/packaging/obs/obs-project.env"
DEBIAN_CONTROL="${ROOT_DIR}/packaging/obs/debian/debian/control"
VLZ_CARGO="${ROOT_DIR}/crates/core/vlz/Cargo.toml"

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

"${ROOT_DIR}/scripts/check-obs-signing.sh" \
  --config "${OBS_ENV}"
