#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/obs-project-env-parse.sh
. "${SCRIPT_DIR}/lib/obs-project-env-parse.sh"
# shellcheck source=lib/osc-cmd.sh
. "${SCRIPT_DIR}/lib/osc-cmd.sh"

readonly DEFAULT_OBS_API="https://api.opensuse.org"
readonly DEFAULT_CONFIG_PATH="packaging/obs/obs-project.env"
readonly DEFAULT_PROJECT_META_REL="packaging/obs/project/_meta"
readonly REPOSITORIES_HELPER="${SCRIPT_DIR}/obs_repositories.py"

usage() {
  cat >&2 <<'EOF'
Usage: sync-obs-project-meta.sh [--push | --pull | --check] [options]

Sync committed OBS project _meta with build.opensuse.org.

Modes (exactly one required):
  --push       Upload packaging/obs/project/_meta to OBS (primary release flow)
  --pull       Fetch live project _meta into the committed path (bootstrap/recovery)
  --check      Fail when live OBS project _meta differs from git

Options:
  --config <path>         OBS coordinate file (default: packaging/obs/obs-project.env)
  --obs-api <url>         OBS API base URL (default: https://api.opensuse.org)
  --project-meta <path>   Project _meta path relative to repo root or absolute
                          (default: packaging/obs/project/_meta)
  --dry-run               Print actions without calling OBS (for --push/--pull)
  -h, --help              Show this help text

Environment (required unless --dry-run):
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

resolve_project_meta_path() {
  if [[ "${PROJECT_META_PATH}" == /* ]]; then
    printf '%s' "${PROJECT_META_PATH}"
    return
  fi
  printf '%s/%s' "${REPO_ROOT}" "${PROJECT_META_PATH}"
}

count_repositories() {
  local meta_file="$1"
  python3 "${REPOSITORIES_HELPER}" \
    --repo-root "${REPO_ROOT}" \
    --project-meta "${meta_file}" \
    --package-meta "${REPO_ROOT}/packaging/obs/rpm/_meta" \
    | tr ',' '\n' | wc -l
}

CONFIG_PATH="${DEFAULT_CONFIG_PATH}"
OBS_API="${DEFAULT_OBS_API}"
PROJECT_META_PATH="${DEFAULT_PROJECT_META_REL}"
MODE=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --obs-api)
      OBS_API="$2"
      shift 2
      ;;
    --project-meta)
      PROJECT_META_PATH="$2"
      shift 2
      ;;
    --push|--pull|--check)
      if [[ -n "${MODE}" ]]; then
        echo "ERROR: specify only one of --push, --pull, or --check" >&2
        usage
        exit 1
      fi
      MODE="${1#--}"
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

if [[ -z "${MODE}" ]]; then
  echo "ERROR: one of --push, --pull, or --check is required" >&2
  usage
  exit 1
fi

if [[ "${CONFIG_PATH}" != /* ]]; then
  CONFIG_PATH="${REPO_ROOT}/${CONFIG_PATH}"
fi

obs_parse_project_env "${CONFIG_PATH}"

PROJECT_META_FILE="$(resolve_project_meta_path)"

if [[ "${MODE}" == "push" && ! -f "${PROJECT_META_FILE}" ]]; then
  echo "ERROR: OBS project _meta not found: ${PROJECT_META_FILE}" >&2
  exit 1
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "OBS project meta sync dry-run"
  echo "  mode=${MODE}"
  echo "  project=${OBS_PROJECT}"
  echo "  project_meta=${PROJECT_META_FILE}"
  if [[ -f "${PROJECT_META_FILE}" ]]; then
    echo "  repositories=$(count_repositories "${PROJECT_META_FILE}")"
  fi
  exit 0
fi

require_cmd osc
require_cmd python3
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
setup_osc_auth "${WORK_DIR}"

case "${MODE}" in
  push)
    repo_count="$(count_repositories "${PROJECT_META_FILE}")"
    osc_cmd api -X PUT "/source/${OBS_PROJECT}/_meta" --file "${PROJECT_META_FILE}"
    echo "OBS project meta pushed for ${OBS_PROJECT}"
    echo "  project_meta=${PROJECT_META_FILE}"
    echo "  repositories=${repo_count}"
    ;;
  pull)
    mkdir -p "$(dirname "${PROJECT_META_FILE}")"
    osc_cmd api "/source/${OBS_PROJECT}/_meta" >"${PROJECT_META_FILE}"
    repo_count="$(count_repositories "${PROJECT_META_FILE}")"
    echo "OBS project meta pulled for ${OBS_PROJECT}"
    echo "  project_meta=${PROJECT_META_FILE}"
    echo "  repositories=${repo_count}"
    ;;
  check)
    if [[ ! -f "${PROJECT_META_FILE}" ]]; then
      echo "ERROR: OBS project _meta not found: ${PROJECT_META_FILE}" >&2
      exit 1
    fi
    live_meta="${WORK_DIR}/live-meta.xml"
    osc_cmd api "/source/${OBS_PROJECT}/_meta" >"${live_meta}"
    if ! diff -u "${PROJECT_META_FILE}" "${live_meta}" >/dev/null; then
      echo "ERROR: OBS project _meta drift detected for ${OBS_PROJECT}" >&2
      echo "  committed=${PROJECT_META_FILE}" >&2
      echo "  hint: edit git and --push, or run --pull to reconcile" >&2
      diff -u "${PROJECT_META_FILE}" "${live_meta}" >&2 || true
      exit 1
    fi
    echo "OBS project meta matches live OBS for ${OBS_PROJECT}"
    ;;
esac
