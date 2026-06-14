# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared verification helpers for OBS release source uploads.
# shellcheck shell=bash

obs_verify_vendor_lockfile() {
  local repo_root="$1"
  local git_ref="$2"
  local vendor_archive="$3"
  env PYTHONPATH="${repo_root}" python3 "${repo_root}/scripts/obs_upload_verify.py" \
    vendor-lockfile \
    --repo-root "${repo_root}" \
    --git-ref "${git_ref}" \
    --vendor-archive "${vendor_archive}"
}

obs_verify_package_checksums() {
  local repo_root="$1"
  local package_dir="$2"
  shift 2
  local -a verify_args=(
    env PYTHONPATH="${repo_root}"
    python3 "${repo_root}/scripts/obs_upload_verify.py"
    package-checksums
    --package-dir "${package_dir}"
  )
  local item=""
  for item in "$@"; do
    verify_args+=(--expected "${item}")
  done
  "${verify_args[@]}"
}
