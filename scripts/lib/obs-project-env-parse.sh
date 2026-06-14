# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Parse packaging/obs/obs-project.env. Sourced by OBS automation scripts.
# shellcheck shell=bash

obs_env_trim() {
  local value="$1"
  # shellcheck disable=SC2001
  value="$(echo "${value}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [[ "${#value}" -ge 2 && "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "${value}"
}

obs_parse_project_env() {
  local env_path="$1"
  local line key value
  if [[ ! -f "${env_path}" ]]; then
    echo "ERROR: OBS config file not found: ${env_path}" >&2
    return 1
  fi

  OBS_PROJECT=""
  OBS_PACKAGE=""
  OBS_SPEC_FILENAME=""
  OBS_CHANGES_FILENAME=""
  OBS_LEGACY_CHANGES_FILENAME=""
  OBS_MAINTAINER=""
  OBS_WAIT_TIMEOUT_SECONDS=""
  OBS_WAIT_POLL_INTERVAL_SECONDS=""

  while IFS= read -r line; do
    line="$(obs_env_trim "${line}")"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="$(obs_env_trim "${key}")"
    value="$(obs_env_trim "${value}")"
    case "${key}" in
      OBS_PROJECT) OBS_PROJECT="${value}" ;;
      OBS_PACKAGE) OBS_PACKAGE="${value}" ;;
      OBS_SPEC_FILENAME) OBS_SPEC_FILENAME="${value}" ;;
      OBS_CHANGES_FILENAME) OBS_CHANGES_FILENAME="${value}" ;;
      OBS_LEGACY_CHANGES_FILENAME) OBS_LEGACY_CHANGES_FILENAME="${value}" ;;
      OBS_MAINTAINER) OBS_MAINTAINER="${value}" ;;
      OBS_WAIT_TIMEOUT_SECONDS) OBS_WAIT_TIMEOUT_SECONDS="${value}" ;;
      OBS_WAIT_POLL_INTERVAL_SECONDS) OBS_WAIT_POLL_INTERVAL_SECONDS="${value}" ;;
      *)
        echo "ERROR: unsupported key in ${env_path}: ${key}" >&2
        return 1
        ;;
    esac
  done <"${env_path}"

  if [[ -z "${OBS_PROJECT}" ]]; then
    echo "ERROR: OBS_PROJECT is missing in ${env_path}" >&2
    return 1
  fi
  if [[ -z "${OBS_PACKAGE}" ]]; then
    echo "ERROR: OBS_PACKAGE is missing in ${env_path}" >&2
    return 1
  fi

  OBS_SPEC_FILENAME="${OBS_SPEC_FILENAME:-verilyze.spec}"
  OBS_CHANGES_FILENAME="${OBS_CHANGES_FILENAME:-verilyze.changes}"
  OBS_LEGACY_CHANGES_FILENAME="${OBS_LEGACY_CHANGES_FILENAME:-verilyze.spec.changes}"
  OBS_MAINTAINER="${OBS_MAINTAINER:-Travis Post <post.travis@gmail.com>}"
  export OBS_WAIT_TIMEOUT_SECONDS OBS_WAIT_POLL_INTERVAL_SECONDS
}
