#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# NFR-006 / HC-6: build the vlz release binary twice into clean target dirs
# and require identical SHA-256 digests. Quiet by default; stream cargo output
# when VLZ_CHECK_VERBOSE=1.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# shellcheck source=lib/check-quiet-env.sh
source "${ROOT}/scripts/lib/check-quiet-env.sh"
# shellcheck source=lib/reproducible-build-env.sh
source "${ROOT}/scripts/lib/reproducible-build-env.sh"
vlz_apply_check_log_env
vlz_apply_reproducible_build_env "${ROOT}"

mkdir -p "${ROOT}/target"
_dir_a="$(mktemp -d "${ROOT}/target/repro-a.XXXXXX")"
_dir_b="$(mktemp -d "${ROOT}/target/repro-b.XXXXXX")"
_cargo_log="$(mktemp)"
_cleanup() {
  rm -rf "${_dir_a}" "${_dir_b}"
  rm -f "${_cargo_log}"
}
trap _cleanup EXIT

_build_once() {
  local target_dir="$1"
  local log_file="$2"
  # Preserve caller RUSTFLAGS (includes remap + optional -Dwarnings).
  env CARGO_TARGET_DIR="${target_dir}" \
    cargo build --release --locked -p vlz >>"${log_file}" 2>&1
}

set +e
_build_once "${_dir_a}" "${_cargo_log}"
_ec_a=$?
_build_once "${_dir_b}" "${_cargo_log}"
_ec_b=$?
set -e

if vlz_check_verbose_enabled || [[ "${_ec_a}" -ne 0 || "${_ec_b}" -ne 0 ]]; then
  cat "${_cargo_log}" >&2
fi
if [[ "${_ec_a}" -ne 0 ]]; then
  echo "ERROR: first reproducible build failed (exit ${_ec_a})" >&2
  exit "${_ec_a}"
fi
if [[ "${_ec_b}" -ne 0 ]]; then
  echo "ERROR: second reproducible build failed (exit ${_ec_b})" >&2
  exit "${_ec_b}"
fi

_bin_a="${_dir_a}/release/vlz"
_bin_b="${_dir_b}/release/vlz"
if [[ ! -f "${_bin_a}" || ! -f "${_bin_b}" ]]; then
  echo "ERROR: expected release/vlz in both target dirs" >&2
  exit 1
fi

_hash_a="$(sha256sum "${_bin_a}" | awk '{print $1}')"
_hash_b="$(sha256sum "${_bin_b}" | awk '{print $1}')"

if [[ "${_hash_a}" != "${_hash_b}" ]]; then
  echo "ERROR: reproducible build mismatch (NFR-006)" >&2
  echo "  build A: ${_hash_a}" >&2
  echo "  build B: ${_hash_b}" >&2
  echo "  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" >&2
  echo "  RUSTFLAGS=${RUSTFLAGS}" >&2
  exit 1
fi

if vlz_check_verbose_enabled; then
  echo "reproducible build OK sha256=${_hash_a} SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" >&2
fi
