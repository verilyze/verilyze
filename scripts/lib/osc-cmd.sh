# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared osc invocation helpers for OBS automation scripts.
# shellcheck shell=bash

osc_cmd() {
  local -a config_args=()
  if [[ -n "${OSC_CONFIG:-}" ]]; then
    config_args=(--config "${OSC_CONFIG}")
  fi
  osc --no-keyring "${config_args[@]}" -A "${OBS_API}" "$@"
}

setup_osc_auth() {
  local work_dir="$1"
  local obs_user="${OBS_USER:-${OSC_USERNAME:-}}"
  local obs_password="${OBS_PASSWORD:-${OSC_PASSWORD:-}}"
  if [[ -z "${obs_user}" || -z "${obs_password}" ]]; then
    echo "ERROR: OBS_USER and OBS_PASSWORD (or OSC_* equivalents) are required" >&2
    exit 1
  fi
  local oscrc="${work_dir}/oscrc"
  cat >"${oscrc}" <<EOF
[general]
apiurl = ${OBS_API}
use_keyring = 0
EOF
  chmod 600 "${oscrc}"
  export OSC_CONFIG="${oscrc}"
  export OSC_APIURL="${OBS_API}"
  export OBS_USER="${obs_user}"
  export OBS_PASSWORD="${obs_password}"
  export OSC_USERNAME="${obs_user}"
  export OSC_PASSWORD="${obs_password}"
}
