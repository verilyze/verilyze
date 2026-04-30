#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

readonly DEFAULT_CONFIG_PATH="packaging/obs/obs-project.env"
readonly DEFAULT_OBS_WEB_URL="https://build.opensuse.org"
readonly DEFAULT_MIN_VALID_DAYS="30"

usage() {
  cat >&2 <<'EOF'
Usage: check-obs-signing.sh [options]

Options:
  --config <path>              OBS coordinate file
                               (default: packaging/obs/obs-project.env)
  --obs-web <url>              OBS web base URL
                               (default: https://build.opensuse.org)
  --signing-keys-file <path>   Read signing metadata from a local file
  --min-valid-days <days>      Minimum remaining key validity in days
                               (default: 30)
  -h, --help                   Show this help text
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

extract_fingerprint() {
  local source_file="$1"
  python3 - "$source_file" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    (
        r"<dt[^>]*>\s*Fingerprint\s*</dt>\s*"
        r"<dd[^>]*>\s*([0-9a-fA-F ]{16,})\s*</dd>"
    ),
    text,
    flags=re.IGNORECASE | re.DOTALL,
)
if not match:
    sys.exit(1)
fingerprint = " ".join(match.group(1).split()).lower()
print(fingerprint)
PY
}

extract_expiry_date() {
  local source_file="$1"
  python3 - "$source_file" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    (
        r"<dt[^>]*>\s*Expires on\s*</dt>\s*"
        r"<dd[^>]*>\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\s*</dd>"
    ),
    text,
    flags=re.IGNORECASE | re.DOTALL,
)
if not match:
    sys.exit(1)
print(match.group(1))
PY
}

days_until_expiry() {
  local expires_on="$1"
  python3 - "$expires_on" <<'PY'
from datetime import UTC, date, datetime
import sys

expiry = date.fromisoformat(sys.argv[1])
today = datetime.now(UTC).date()
print((expiry - today).days)
PY
}

CONFIG_PATH="${DEFAULT_CONFIG_PATH}"
OBS_WEB_URL="${DEFAULT_OBS_WEB_URL}"
MIN_VALID_DAYS="${DEFAULT_MIN_VALID_DAYS}"
SIGNING_KEYS_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --obs-web)
      OBS_WEB_URL="$2"
      shift 2
      ;;
    --signing-keys-file)
      SIGNING_KEYS_FILE="$2"
      shift 2
      ;;
    --min-valid-days)
      MIN_VALID_DAYS="$2"
      shift 2
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

if ! [[ "${MIN_VALID_DAYS}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --min-valid-days must be a non-negative integer." >&2
  exit 1
fi

parse_obs_project_env "${CONFIG_PATH}"

if [[ -n "${SIGNING_KEYS_FILE}" ]]; then
  if [[ ! -f "${SIGNING_KEYS_FILE}" ]]; then
    echo "ERROR: signing keys file not found: ${SIGNING_KEYS_FILE}" >&2
    exit 1
  fi
  SOURCE_FILE="${SIGNING_KEYS_FILE}"
else
  require_cmd curl
  SOURCE_FILE="$(mktemp)"
  trap 'rm -f "${SOURCE_FILE}"' EXIT
  SIGNING_KEYS_URL="${OBS_WEB_URL}/projects/${OBS_PROJECT}/signing_keys"
  curl --fail --silent --show-error "${SIGNING_KEYS_URL}" >"${SOURCE_FILE}"
fi

if ! fingerprint="$(extract_fingerprint "${SOURCE_FILE}")"; then
  echo "ERROR: could not find OBS project key fingerprint metadata." >&2
  exit 1
fi

if ! expires_on="$(extract_expiry_date "${SOURCE_FILE}")"; then
  echo "ERROR: could not find OBS project key expiration metadata." >&2
  exit 1
fi

days_remaining="$(days_until_expiry "${expires_on}")"
if [[ "${days_remaining}" -lt "${MIN_VALID_DAYS}" ]]; then
  echo "ERROR: OBS signing key expires too soon: ${expires_on}" >&2
  echo "  days_remaining=${days_remaining}" >&2
  echo "  min_valid_days=${MIN_VALID_DAYS}" >&2
  exit 1
fi

echo "OBS signing key metadata OK for ${OBS_PROJECT}/${OBS_PACKAGE}"
echo "  fingerprint=${fingerprint}"
echo "  expires_on=${expires_on}"
echo "  days_remaining=${days_remaining}"
