#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Sync crate-local assets used by the publishable vlz package.
# Usage: sync-vlz-crate-assets.sh [--check]

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=lib/check-quiet-env.sh
source "${script_dir}/lib/check-quiet-env.sh"

check_mode=0
if [[ "${1:-}" == "--check" ]]; then
  check_mode=1
fi

assets_dir="${root}/crates/core/vlz/assets"
config_src="${root}/scripts/config-comments.toml"
config_dst="${assets_dir}/config-comments.toml"
man_src="${root}/man/vlz.1"
man_dst="${assets_dir}/vlz.1"

sync_file() {
  local src="$1"
  local dst="$2"
  if [[ ! -f "${src}" ]]; then
    echo "error: missing source file ${src}" >&2
    return 1
  fi
  if [[ "${check_mode}" -eq 1 ]]; then
    if [[ ! -f "${dst}" ]] || ! cmp -s "${src}" "${dst}"; then
      echo "error: ${dst#"${root}/"} is out of sync; run make sync-vlz-crate-assets" >&2
      return 1
    fi
    return 0
  fi
  mkdir -p "$(dirname "${dst}")"
  cp "${src}" "${dst}"
}

sync_file "${config_src}" "${config_dst}"
sync_file "${man_src}" "${man_dst}"

if [[ "${check_mode}" -eq 0 ]]; then
  PYTHONPATH="${root}" python3 "${script_dir}/sync_vlz_build_metadata.py"
else
  PYTHONPATH="${root}" python3 "${script_dir}/sync_vlz_build_metadata.py" --check
fi
