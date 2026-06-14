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
readonly DEFAULT_SPEC_TEMPLATE="packaging/obs/rpm/verilyze.spec"
readonly DEFAULT_SEED_CHANGES="packaging/obs/rpm/verilyze.changes"
readonly DEFAULT_CHANGELOG="CHANGELOG.md"
readonly RENDER_CHANGES_SCRIPT="scripts/render_obs_changes.py"
readonly VENDOR_ARCHIVE_NAME="vendor.tar.zst"

usage() {
  cat >&2 <<'EOF'
Usage: obs-upload-release-sources.sh --version <semver> [options]

Build release sources for OBS (upstream tarball, vendor archive, spec) and
upload them with osc. Intended for build.opensuse.org where cargo_vendor and
tar source services are unavailable.

Options:
  --config <path>         OBS coordinate file (default: packaging/obs/obs-project.env)
  --spec-template <path>  RPM spec template (default: packaging/obs/rpm/verilyze.spec)
  --seed-changes <path>   Seed .changes when OBS checkout has none (default: packaging/obs/rpm/verilyze.changes)
  --changelog <path>      Release changelog source (default: CHANGELOG.md)
  --work-dir <path>       Staging directory (default: temporary directory)
  --git-ref <ref>         Git tree to archive (default: HEAD)
  --obs-api <url>         OBS API base URL (default: https://api.opensuse.org)
  --dry-run               Build artifacts locally; skip osc upload
  -h, --help              Show this help text

Environment (required unless --dry-run):
  OBS_USER                OBS account for osc upload
  OBS_PASSWORD            OBS password or API token for osc upload
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

render_changes_file() {
  local version="$1"
  local output_path="$2"
  local existing_path="${3:-}"
  local render_args=(
    env PYTHONPATH="${REPO_ROOT}"
    python3 "${REPO_ROOT}/${RENDER_CHANGES_SCRIPT}"
    --version "${version}"
    --changelog "${REPO_ROOT}/${CHANGELOG_PATH}"
    --config "${REPO_ROOT}/${CONFIG_PATH}"
    --output "${output_path}"
  )
  if [[ -n "${existing_path}" && -f "${existing_path}" ]]; then
    render_args+=(--existing-changes "${existing_path}")
  elif [[ -f "${REPO_ROOT}/${SEED_CHANGES_PATH}" ]]; then
    render_args+=(--seed-changes "${REPO_ROOT}/${SEED_CHANGES_PATH}")
  fi
  "${render_args[@]}"
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
  else
    sha256 -r "${path}" | awk '{print $1}'
  fi
}

build_source_archive() {
  local git_ref="$1"
  local version="$2"
  local output_path="$3"
  local archive_prefix="${OBS_PACKAGE}-${version}/"
  git archive --format=tar --prefix="${archive_prefix}" "${git_ref}" | xz -c >"${output_path}"
}

build_vendor_archive() {
  local git_ref="$1"
  local work_dir="$2"
  local output_path="$3"
  local vendor_root="${work_dir}/vendor-build"
  rm -rf "${vendor_root}"
  mkdir -p "${vendor_root}"
  git archive --format=tar "${git_ref}" | tar -x -C "${vendor_root}"
  (
    cd "${vendor_root}"
    cargo vendor --locked vendor
    mkdir -p .cargo
    cat >.cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
    tar --zstd -cf "${output_path}" .cargo vendor Cargo.lock
  )
}

render_spec() {
  local version="$1"
  local template_path="$2"
  local output_path="$3"
  sed -E "s/^Version:[[:space:]]+.*/Version:        ${version}/" \
    "${template_path}" >"${output_path}"
}

osc_checkout_package() {
  local project="$1"
  local package="$2"
  if osc_cmd help co 2>&1 | grep -q -- '--nosource'; then
    osc_cmd co --nosource "${project}" "${package}"
  else
    # Ubuntu/apt osc lacks --nosource. Full checkout is required: metadata-only
    # checkouts include _meta without sha256 sums and osc commit then fails.
    # -c places the package dir in cwd (not PROJECT/PACKAGE).
    osc_cmd co -c "${project}" "${package}"
  fi
}

upload_to_obs() {
  local work_dir="$1"
  local version="$2"
  local checkout_dir="${work_dir}/osc-checkout"
  local source_archive="${OBS_PACKAGE}-${version}.tar.xz"
  local existing_changes=""
  rm -rf "${checkout_dir}"
  mkdir -p "${checkout_dir}"
  (
    cd "${checkout_dir}"
    osc_checkout_package "${OBS_PROJECT}" "${OBS_PACKAGE}"
    cd "${OBS_PACKAGE}"
    if [[ -f "${OBS_CHANGES_FILENAME}" ]]; then
      existing_changes="${PWD}/${OBS_CHANGES_FILENAME}"
    fi
    render_changes_file "${version}" "${OBS_CHANGES_FILENAME}" "${existing_changes}"
    cp "${work_dir}/${source_archive}" .
    cp "${work_dir}/${VENDOR_ARCHIVE_NAME}" .
    cp "${work_dir}/${OBS_SPEC_FILENAME}" .
    osc_cmd add \
      "${source_archive}" \
      "${VENDOR_ARCHIVE_NAME}" \
      "${OBS_SPEC_FILENAME}" \
      "${OBS_CHANGES_FILENAME}" \
      2>/dev/null || true
    if [[ -f "${OBS_LEGACY_CHANGES_FILENAME}" ]]; then
      osc_cmd delete "${OBS_LEGACY_CHANGES_FILENAME}" 2>/dev/null || rm -f "${OBS_LEGACY_CHANGES_FILENAME}"
    fi
    osc_cmd commit -m "Upload release ${version} sources from GitHub Actions"
  )
}

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_PATH="${DEFAULT_CONFIG_PATH}"
SPEC_TEMPLATE="${DEFAULT_SPEC_TEMPLATE}"
SEED_CHANGES_PATH="${DEFAULT_SEED_CHANGES}"
CHANGELOG_PATH="${DEFAULT_CHANGELOG}"
WORK_DIR=""
GIT_REF="HEAD"
OBS_API="${DEFAULT_OBS_API}"
VERSION=""
DRY_RUN=0
OBS_USER="${OBS_USER:-}"
OBS_PASSWORD="${OBS_PASSWORD:-}"
TEMP_WORK_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --spec-template)
      SPEC_TEMPLATE="$2"
      shift 2
      ;;
    --seed-changes)
      SEED_CHANGES_PATH="$2"
      shift 2
      ;;
    --changelog)
      CHANGELOG_PATH="$2"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="$2"
      shift 2
      ;;
    --git-ref)
      GIT_REF="$2"
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

if [[ ! -f "${REPO_ROOT}/${SPEC_TEMPLATE}" ]]; then
  echo "ERROR: spec template not found: ${REPO_ROOT}/${SPEC_TEMPLATE}" >&2
  exit 1
fi

obs_parse_project_env "${REPO_ROOT}/${CONFIG_PATH}"

if [[ -z "${WORK_DIR}" ]]; then
  TEMP_WORK_DIR="$(mktemp -d)"
  WORK_DIR="${TEMP_WORK_DIR}"
fi
mkdir -p "${WORK_DIR}"

require_cmd git
require_cmd cargo
require_cmd tar
require_cmd sed
require_cmd xz
require_cmd python3

SOURCE_ARCHIVE="${OBS_PACKAGE}-${VERSION}.tar.xz"
SOURCE_PATH="${WORK_DIR}/${SOURCE_ARCHIVE}"
VENDOR_PATH="${WORK_DIR}/${VENDOR_ARCHIVE_NAME}"
SPEC_PATH="${WORK_DIR}/${OBS_SPEC_FILENAME}"
CHANGES_PATH="${WORK_DIR}/${OBS_CHANGES_FILENAME}"

echo "Building OBS release sources (version=${VERSION})"
build_source_archive "${GIT_REF}" "${VERSION}" "${SOURCE_PATH}"
build_vendor_archive "${GIT_REF}" "${WORK_DIR}" "${VENDOR_PATH}"
render_spec "${VERSION}" "${REPO_ROOT}/${SPEC_TEMPLATE}" "${SPEC_PATH}"
render_changes_file "${VERSION}" "${CHANGES_PATH}"

echo "OBS upload dry-run summary"
echo "  project=${OBS_PROJECT}"
echo "  package=${OBS_PACKAGE}"
echo "  version=${VERSION}"
echo "  source_archive=${SOURCE_ARCHIVE}"
echo "  source_sha256=$(sha256_file "${SOURCE_PATH}")"
echo "  vendor_archive=${VENDOR_ARCHIVE_NAME}"
echo "  vendor_sha256=$(sha256_file "${VENDOR_PATH}")"
echo "  spec=${OBS_SPEC_FILENAME}"
echo "  spec_sha256=$(sha256_file "${SPEC_PATH}")"
echo "  changes=${OBS_CHANGES_FILENAME}"
echo "  changes_sha256=$(sha256_file "${CHANGES_PATH}")"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "Dry-run complete (no osc upload)."
  if [[ -n "${TEMP_WORK_DIR}" ]]; then
    rm -rf "${TEMP_WORK_DIR}"
  fi
  exit 0
fi

require_cmd osc
setup_osc_auth "${WORK_DIR}"
upload_to_obs "${WORK_DIR}" "${VERSION}"
echo "OBS source upload completed."

if [[ -n "${TEMP_WORK_DIR}" ]]; then
  rm -rf "${TEMP_WORK_DIR}"
fi
