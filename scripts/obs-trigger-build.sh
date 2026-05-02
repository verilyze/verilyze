#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Base URL for OBS /trigger/* HTTP endpoints (build.opensuse.org), not api.opensuse.org.
readonly DEFAULT_OBS_TRIGGER_BASE="https://build.opensuse.org"

usage() {
  cat >&2 <<'EOF'
Usage: obs-trigger-build.sh --version <semver> [options]

Options:
  --config <path>         OBS coordinate file (default: packaging/obs/obs-project.env)
  --obs-trigger-base <url>  Base URL for POST /trigger/runservice and /trigger/rebuild
                            (default: https://build.opensuse.org)
  --obs-api <url>         Same as --obs-trigger-base (deprecated alias)
  --token-runservice <t>  Token for runservice (default: OBS_TOKEN_RUNSERVICE)
  --token-rebuild <t>   Token for rebuild (default: OBS_TOKEN_REBUILD)
  --dry-run               Print planned requests without calling OBS
  -h, --help              Show this help text

Environment:
  OBS_TOKEN_RUNSERVICE   OBS authorization token for trigger/runservice
  OBS_TOKEN_REBUILD      OBS authorization token for trigger/rebuild
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
OBS_TRIGGER_BASE="${DEFAULT_OBS_TRIGGER_BASE}"
VERSION=""
TOKEN_RUNSERVICE="${OBS_TOKEN_RUNSERVICE:-}"
TOKEN_REBUILD="${OBS_TOKEN_REBUILD:-}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --obs-trigger-base)
      OBS_TRIGGER_BASE="$2"
      shift 2
      ;;
    --obs-api)
      OBS_TRIGGER_BASE="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --token-runservice)
      TOKEN_RUNSERVICE="$2"
      shift 2
      ;;
    --token-rebuild)
      TOKEN_REBUILD="$2"
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
RUNSERVICE_URL="${OBS_TRIGGER_BASE}/trigger/runservice?project=${PROJECT_SEGMENT}&package=${PACKAGE_SEGMENT}"
REBUILD_URL="${OBS_TRIGGER_BASE}/trigger/rebuild?project=${PROJECT_SEGMENT}&package=${PACKAGE_SEGMENT}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "OBS dry-run"
  echo "  version=${VERSION}"
  echo "  project=${OBS_PROJECT}"
  echo "  package=${OBS_PACKAGE}"
  echo "  obs_trigger_base=${OBS_TRIGGER_BASE}"
  echo "  runservice_url=${RUNSERVICE_URL}"
  echo "  rebuild_url=${REBUILD_URL}"
  exit 0
fi

if [[ -z "${TOKEN_RUNSERVICE}" ]]; then
  echo "ERROR: OBS runservice token is required (set OBS_TOKEN_RUNSERVICE or --token-runservice)" >&2
  exit 1
fi
if [[ -z "${TOKEN_REBUILD}" ]]; then
  echo "ERROR: OBS rebuild token is required (set OBS_TOKEN_REBUILD or --token-rebuild)" >&2
  exit 1
fi

require_cmd curl

echo "Triggering OBS runservice for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Token ${TOKEN_RUNSERVICE}" \
  "${RUNSERVICE_URL}" >/dev/null

echo "Triggering OBS rebuild for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Token ${TOKEN_REBUILD}" \
  "${REBUILD_URL}" >/dev/null

echo "OBS trigger completed."
