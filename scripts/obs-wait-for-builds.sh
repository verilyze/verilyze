#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/obs-project-env-parse.sh
. "${SCRIPT_DIR}/lib/obs-project-env-parse.sh"
# shellcheck source=lib/osc-cmd.sh
. "${SCRIPT_DIR}/lib/osc-cmd.sh"

readonly DEFAULT_OBS_API="https://api.opensuse.org"
readonly DEFAULT_CONFIG_PATH="packaging/obs/obs-project.env"
readonly DEFAULT_WAIT_TIMEOUT_SECONDS=7200
readonly DEFAULT_WAIT_POLL_INTERVAL_SECONDS=60
readonly STATUS_HELPER="${SCRIPT_DIR}/obs_wait_build_status.py"
readonly REPOSITORIES_HELPER="${SCRIPT_DIR}/obs_repositories.py"

usage() {
  cat >&2 <<'EOF'
Usage: obs-wait-for-builds.sh --version <semver> [options]

Poll OBS until configured repositories finish building the package.

Options:
  --config <path>       OBS coordinate file (default: packaging/obs/obs-project.env)
  --repo-root <path>    Repository root for _meta derivation (default: repo root)
  --obs-api <url>       OBS API base URL (default: https://api.opensuse.org)
  --version <semver>    Release version (for logging)
  --timeout <seconds>   Override OBS_WAIT_TIMEOUT_SECONDS
  --poll-interval <sec> Override OBS_WAIT_POLL_INTERVAL_SECONDS
  --repositories <list> Comma-separated repository names (default: derive from _meta)
  --results-file <path> Use XML from a file instead of osc api (tests/local)
  --dry-run             Print wait plan without polling OBS
  -h, --help            Show this help text

Environment (required unless --results-file is used):
  OBS_USER / OSC_USERNAME
  OBS_PASSWORD / OSC_PASSWORD
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

fetch_build_results() {
  if [[ -n "${RESULTS_FILE}" ]]; then
    cat "${RESULTS_FILE}"
    return
  fi
  osc_cmd api "/build/${OBS_PROJECT}/_result?package=${OBS_PACKAGE}"
}

evaluate_results() {
  local xml_text="$1"
  local xml_file
  xml_file="$(mktemp)"
  printf '%s' "${xml_text}" >"${xml_file}"
  python3 "${STATUS_HELPER}" \
    --package "${OBS_PACKAGE}" \
    --repositories "${OBS_WAIT_REPOSITORIES}" \
    --xml-file "${xml_file}"
  rm -f "${xml_file}"
}

resolve_wait_repositories() {
  if [[ -n "${REPOSITORIES_OVERRIDE}" ]]; then
    OBS_WAIT_REPOSITORIES="${REPOSITORIES_OVERRIDE}"
    return
  fi
  OBS_WAIT_REPOSITORIES="$(
    python3 "${REPOSITORIES_HELPER}" --repo-root "${REPO_ROOT}"
  )"
  if [[ -z "${OBS_WAIT_REPOSITORIES}" ]]; then
    echo "ERROR: no enabled OBS repositories derived from _meta files" >&2
    exit 1
  fi
}

CONFIG_PATH="${DEFAULT_CONFIG_PATH}"
REPO_ROOT=""
OBS_API="${DEFAULT_OBS_API}"
VERSION=""
TIMEOUT_SECONDS=""
POLL_INTERVAL_SECONDS=""
REPOSITORIES_OVERRIDE=""
RESULTS_FILE=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --repo-root)
      REPO_ROOT="$2"
      shift 2
      ;;
    --obs-api)
      OBS_API="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --poll-interval)
      POLL_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --repositories)
      REPOSITORIES_OVERRIDE="$2"
      shift 2
      ;;
    --results-file)
      RESULTS_FILE="$2"
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

if [[ -z "${REPO_ROOT}" ]]; then
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

if [[ -z "${VERSION}" ]]; then
  echo "ERROR: --version is required" >&2
  usage
  exit 1
fi

obs_parse_project_env "${CONFIG_PATH}"

require_cmd python3
resolve_wait_repositories

TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-${OBS_WAIT_TIMEOUT_SECONDS:-${DEFAULT_WAIT_TIMEOUT_SECONDS}}}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-${OBS_WAIT_POLL_INTERVAL_SECONDS:-${DEFAULT_WAIT_POLL_INTERVAL_SECONDS}}}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "OBS wait dry-run"
  echo "  version=${VERSION}"
  echo "  project=${OBS_PROJECT}"
  echo "  package=${OBS_PACKAGE}"
  echo "  repositories=${OBS_WAIT_REPOSITORIES}"
  echo "  timeout_seconds=${TIMEOUT_SECONDS}"
  echo "  poll_interval_seconds=${POLL_INTERVAL_SECONDS}"
  exit 0
fi

if [[ -z "${RESULTS_FILE}" ]]; then
  require_cmd osc
  WORK_DIR="$(mktemp -d)"
  setup_osc_auth "${WORK_DIR}"
fi

deadline=$((SECONDS + TIMEOUT_SECONDS))
while true; do
  xml_text="$(fetch_build_results)"
  eval_output="$(evaluate_results "${xml_text}")"
  if ! eval "${eval_output}"; then
    echo "ERROR: failed to evaluate OBS build results" >&2
    exit 1
  fi

  if [[ "${ANY_FAILED}" -eq 1 ]]; then
    echo "ERROR: OBS builds failed for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})" >&2
    if [[ -n "${FAILURES}" ]]; then
      echo "  failures=${FAILURES}" >&2
    fi
    exit 1
  fi

  if [[ "${ALL_SUCCEEDED}" -eq 1 ]]; then
    echo "OBS builds succeeded for ${OBS_PROJECT}/${OBS_PACKAGE} (${VERSION})"
    echo "  matched=${MATCHED}"
    exit 0
  fi

  if (( SECONDS >= deadline )); then
    echo "ERROR: timed out waiting for OBS builds (${TIMEOUT_SECONDS}s)" >&2
    echo "  pending=${PENDING} matched=${MATCHED}" >&2
    if [[ -n "${PENDING_TARGETS}" ]]; then
      echo "  pending_targets=${PENDING_TARGETS}" >&2
    fi
    exit 1
  fi

  echo "OBS builds pending for ${OBS_PROJECT}/${OBS_PACKAGE}: ${PENDING} target(s)"
  if [[ -n "${PENDING_TARGETS}" ]]; then
    echo "  pending_targets=${PENDING_TARGETS}"
  fi
  sleep "${POLL_INTERVAL_SECONDS}"
done
