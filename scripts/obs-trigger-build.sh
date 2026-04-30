#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: obs-trigger-build.sh --version <semver> [options]

Options:
  --config <path>     OBS coordinate file (default: packaging/obs/obs-project.env)
  --obs-api <url>     OBS API base URL (default: https://api.opensuse.org)
  --token <token>     OBS token (default: read OBS_TOKEN env var)
  --dry-run           Print planned requests without calling OBS
  -h, --help          Show this help text
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

trim() {
  local value="$1"
  # shellcheck disable=SC2001
  value="$(echo "${value}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf '%s' "${value}"
}

parse_obs_project_env() {
  local env_path="$1"
  local line key value
  if [[ ! -f "${env_path}" ]]; then
    echo "ERROR: OBS config file not found: ${env_path}" >&2
    exit 1
  fi

  while IFS= read -r line; do
    line="$(trim "${line}")"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="$(trim "${key}")"
    value="$(trim "${value}")"
    case "${key}" in
      OBS_PROJECT) OBS_PROJECT="${value}" ;;
      OBS_PACKAGE) OBS_PACKAGE="${value}" ;;
      *)
        echo "ERROR: unsupported key in ${env_path}: ${key}" >&2
        exit 1
        ;;
    esac
  done <"${env_path}"

  if [[ -z "${OBS_PROJECT:-}" ]]; then
    echo "ERROR: OBS_PROJECT is missing in ${env_path}" >&2
    exit 1
  fi
  if [[ -z "${OBS_PACKAGE:-}" ]]; then
    echo "ERROR: OBS_PACKAGE is missing in ${env_path}" >&2
    exit 1
  fi
}

urlencode_path_segment() {
  local s="$1"
  s="${s//%/%25}"
  s="${s//\//%2F}"
  s="${s//:/%3A}"
  printf '%s' "${s}"
}

CONFIG_PATH="packaging/obs/obs-project.env"
OBS_API_URL="https://api.opensuse.org"
VERSION=""
TOKEN="${OBS_TOKEN:-}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --obs-api)
      OBS_API_URL="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  echo "ERROR: --version is required" >&2
  usage
  exit 1
fi

parse_obs_project_env "${CONFIG_PATH}"

PROJECT_SEGMENT="$(urlencode_path_segment "${OBS_PROJECT}")"
PACKAGE_SEGMENT="$(urlencode_path_segment "${OBS_PACKAGE}")"
RUNSERVICE_URL="${OBS_API_URL}/source/${PROJECT_SEGMENT}/${PACKAGE_SEGMENT}?cmd=runservice"
REBUILD_URL="${OBS_API_URL}/build/${PROJECT_SEGMENT}?cmd=rebuild&package=${OBS_PACKAGE}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "OBS dry-run"
  echo "  version=${VERSION}"
  echo "  project=${OBS_PROJECT}"
  echo "  package=${OBS_PACKAGE}"
  echo "  runservice_url=${RUNSERVICE_URL}"
  echo "  rebuild_url=${REBUILD_URL}"
  exit 0
fi

if [[ -z "${TOKEN}" ]]; then
  echo "ERROR: OBS token is required (set OBS_TOKEN or --token)" >&2
  exit 1
fi

require_cmd curl

echo "Triggering OBS runservice for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Token ${TOKEN}" \
  "${RUNSERVICE_URL}" >/dev/null

echo "Triggering OBS rebuild for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Token ${TOKEN}" \
  "${REBUILD_URL}" >/dev/null

echo "OBS trigger completed."
