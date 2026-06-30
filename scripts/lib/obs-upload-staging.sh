# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# OBS package staging helpers for upload-driven release sources.
# shellcheck shell=bash

obs_file_status_line() {
  local filename="$1"
  osc_cmd status "${filename}" 2>/dev/null | awk -v f="${filename}" '$0 ~ f { print; exit }'
}

obs_file_is_untracked() {
  local filename="$1"
  local line
  line="$(obs_file_status_line "${filename}")"
  [[ "${line}" =~ ^[[:space:]]*\? ]]
}

osc_stage_file_for_commit() {
  local filename="$1"
  if obs_file_is_untracked "${filename}"; then
    osc_cmd add "${filename}"
    return 0
  fi
  if [[ -z "$(obs_file_status_line "${filename}")" ]]; then
    osc_cmd add "${filename}"
  fi
}

osc_commit_package_upload() {
  local message="$1"
  local output=""
  local status=0
  output="$(osc_cmd commit -m "${message}" 2>&1)" || status=$?
  printf '%s\n' "${output}"
  if [[ ${status} -ne 0 ]]; then
    return "${status}"
  fi
  if [[ "${output}" == *"nothing to do"* ]]; then
    echo "ERROR: osc commit made no OBS changes; source archives may be missing" >&2
    return 1
  fi
  return 0
}
