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
  --skip-runservice       Skip trigger/runservice (upload-driven OBS releases)
  --dry-run               Print planned requests without calling OBS
  -h, --help              Show this help text

Environment:
  OBS_TOKEN_RUNSERVICE   OBS authorization token for trigger/runservice
  OBS_TOKEN_REBUILD      OBS authorization token for trigger/rebuild
  OBS_SKIP_RUNSERVICE    When set to 1, same as --skip-runservice
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

print_trigger_failure_hint() {
  local op="$1"
  local url="$2"
  local http_code="$3"
  local body="$4"
  echo "ERROR: OBS ${op} failed with HTTP ${http_code}" >&2
  echo "  target=${OBS_PROJECT}/${OBS_PACKAGE}" >&2
  echo "  url=${url}" >&2
  if [[ -n "${body}" ]]; then
    echo "  response=${body}" >&2
  fi
  if [[ "${http_code}" == "404" && "${body}" == *"Couldn't find Token"* ]]; then
    echo "HINT: OBS did not recognize the token string for this operation." >&2
    echo "HINT: Regenerate the token for the exact project/package and operation." >&2
  elif [[ "${http_code}" == "404" ]]; then
    echo "HINT: HTTP 404 usually means the trigger host, OBS project, or OBS package is wrong." >&2
  fi
  if [[ "${op}" == "runservice" ]]; then
    echo "HINT: Upload-driven releases use --skip-runservice when _service is not used." >&2
  fi
}

trigger_obs_operation() {
  local op="$1"
  local url="$2"
  local token="$3"
  local response_file http_code body curl_status
  response_file="$(mktemp)"
  curl_status=0
  http_code="$(
    curl --silent --show-error \
      --output "${response_file}" \
      --write-out "%{http_code}" \
      --request POST \
      --header "Authorization: Token ${token}" \
      "${url}"
  )" || curl_status=$?
  body="$(<"${response_file}")"
  rm -f "${response_file}"
  if [[ "${curl_status}" -ne 0 ]]; then
    echo "ERROR: OBS ${op} request failed before HTTP response" >&2
    echo "  target=${OBS_PROJECT}/${OBS_PACKAGE}" >&2
    echo "  url=${url}" >&2
    exit 1
  fi
  if [[ ! "${http_code}" =~ ^[0-9]{3}$ ]]; then
    echo "ERROR: OBS ${op} returned invalid HTTP status: ${http_code}" >&2
    echo "  target=${OBS_PROJECT}/${OBS_PACKAGE}" >&2
    echo "  url=${url}" >&2
    exit 1
  fi
  if [[ "${http_code}" -lt 200 || "${http_code}" -ge 300 ]]; then
    print_trigger_failure_hint "${op}" "${url}" "${http_code}" "${body}"
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
SKIP_RUNSERVICE="${OBS_SKIP_RUNSERVICE:-0}"
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
    --skip-runservice)
      SKIP_RUNSERVICE=1
      shift
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
  echo "  skip_runservice=${SKIP_RUNSERVICE}"
  if [[ "${SKIP_RUNSERVICE}" -eq 1 ]]; then
    echo "  rebuild_url=${REBUILD_URL}"
  else
    echo "  runservice_url=${RUNSERVICE_URL}"
    echo "  rebuild_url=${REBUILD_URL}"
  fi
  exit 0
fi

if [[ "${SKIP_RUNSERVICE}" -eq 0 && -z "${TOKEN_RUNSERVICE}" ]]; then
  echo "ERROR: OBS runservice token is required (set OBS_TOKEN_RUNSERVICE or --token-runservice)" >&2
  exit 1
fi
if [[ -z "${TOKEN_REBUILD}" ]]; then
  echo "ERROR: OBS rebuild token is required (set OBS_TOKEN_REBUILD or --token-rebuild)" >&2
  exit 1
fi

require_cmd curl

if [[ "${SKIP_RUNSERVICE}" -eq 0 ]]; then
  echo "Triggering OBS runservice for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
  trigger_obs_operation "runservice" "${RUNSERVICE_URL}" "${TOKEN_RUNSERVICE}"
fi

echo "Triggering OBS rebuild for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
trigger_obs_operation "rebuild" "${REBUILD_URL}" "${TOKEN_REBUILD}"

echo "OBS trigger completed."
