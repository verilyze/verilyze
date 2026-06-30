#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBS_ENV="${ROOT_DIR}/packaging/obs/obs-project.env"
PROJECT_META="${ROOT_DIR}/packaging/obs/project/_meta"
REPOSITORIES_HELPER="${ROOT_DIR}/scripts/obs_repositories.py"
SYNC_META_SCRIPT="${ROOT_DIR}/scripts/sync-obs-project-meta.sh"
DEBIAN_CONTROL="${ROOT_DIR}/packaging/obs/debian/debian/control"
VLZ_CARGO="${ROOT_DIR}/crates/core/vlz/Cargo.toml"
OBS_SERVICE="${ROOT_DIR}/packaging/obs/_service"
OBS_SPEC="${ROOT_DIR}/packaging/obs/rpm/verilyze.spec"

if [[ ! -f "${OBS_ENV}" ]]; then
  echo "ERROR: missing OBS coordinate file: ${OBS_ENV}" >&2
  exit 1
fi

# Use grep (not ripgrep) so CI runners without `rg` still pass (NFR-021).
if ! grep -qE '^OBS_PROJECT=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_PROJECT must be set in ${OBS_ENV}" >&2
  exit 1
fi

if ! grep -qE '^OBS_PACKAGE=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_PACKAGE must be set in ${OBS_ENV}" >&2
  exit 1
fi

if [[ ! -f "${DEBIAN_CONTROL}" ]]; then
  echo "ERROR: missing Debian control file: ${DEBIAN_CONTROL}" >&2
  exit 1
fi

if ! grep -qE '^Package:[[:space:]]+verilyze$' "${DEBIAN_CONTROL}"; then
  echo "ERROR: Debian package name must remain verilyze." >&2
  exit 1
fi

if [[ ! -f "${VLZ_CARGO}" ]]; then
  echo "ERROR: missing Cargo manifest: ${VLZ_CARGO}" >&2
  exit 1
fi

if ! grep -qE '^\[package\.metadata\.deb\]$' "${VLZ_CARGO}"; then
  echo "ERROR: cargo-deb metadata block is required in ${VLZ_CARGO}" >&2
  exit 1
fi

if [[ ! -f "${OBS_SERVICE}" ]]; then
  echo "ERROR: missing OBS source service file: ${OBS_SERVICE}" >&2
  exit 1
fi

if [[ ! -f "${OBS_SPEC}" ]]; then
  echo "ERROR: missing OBS RPM spec: ${OBS_SPEC}" >&2
  exit 1
fi

if ! grep -q -- '--offline' "${OBS_SPEC}"; then
  echo "ERROR: ${OBS_SPEC} must build cargo with --offline" >&2
  exit 1
fi

if ! grep -q 'vendor.tar.zst' "${OBS_SPEC}"; then
  echo "ERROR: ${OBS_SPEC} must declare vendor.tar.zst as Source1" >&2
  exit 1
fi

if ! grep -qE '^%changelog[[:space:]]*$' "${OBS_SPEC}"; then
  echo "ERROR: ${OBS_SPEC} must declare an empty %changelog section for OBS" >&2
  exit 1
fi

if awk '/^%changelog$/{found=1; next} found && NF{exit 1} END{if (!found) exit 1}' \
  "${OBS_SPEC}"; then
  :
else
  echo "ERROR: ${OBS_SPEC} %changelog section must remain empty for OBS" >&2
  exit 1
fi

RENDER_CHANGES_SCRIPT="${ROOT_DIR}/scripts/render_obs_changes.py"
if [[ ! -x "${RENDER_CHANGES_SCRIPT}" ]]; then
  echo "ERROR: missing OBS changes renderer: ${RENDER_CHANGES_SCRIPT}" >&2
  exit 1
fi

if ! grep -qE '^OBS_CHANGES_FILENAME=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_CHANGES_FILENAME must be set in ${OBS_ENV}" >&2
  exit 1
fi

UPLOAD_SCRIPT="${ROOT_DIR}/scripts/obs-upload-release-sources.sh"
if [[ ! -x "${UPLOAD_SCRIPT}" ]]; then
  echo "ERROR: missing OBS upload script: ${UPLOAD_SCRIPT}" >&2
  exit 1
fi

RELEASE_WORKFLOW="${ROOT_DIR}/.github/workflows/release.yml"
if ! grep -q 'obs-upload-release-sources.sh' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must invoke obs-upload-release-sources.sh" >&2
  exit 1
fi
if ! grep -q 'render_obs_changes.py' "${UPLOAD_SCRIPT}"; then
  echo "ERROR: OBS upload script must render .changes via render_obs_changes.py" >&2
  exit 1
fi
if ! grep -q 'OBS_CHANGES_FILENAME' "${UPLOAD_SCRIPT}"; then
  echo "ERROR: OBS upload script must upload OBS_CHANGES_FILENAME" >&2
  exit 1
fi
if ! grep -q 'remove_stale_source_archives' "${UPLOAD_SCRIPT}"; then
  echo "ERROR: OBS upload script must remove stale source tarballs on upload" >&2
  exit 1
fi
if ! grep -q 'obs_verify_vendor_lockfile' "${UPLOAD_SCRIPT}"; then
  echo "ERROR: OBS upload script must verify vendor Cargo.lock before upload" >&2
  exit 1
fi
if ! grep -q 'obs_verify_package_checksums' "${UPLOAD_SCRIPT}"; then
  echo "ERROR: OBS upload script must verify upload checksums after osc commit" >&2
  exit 1
fi
if ! grep -q 'OBS_RPMLINTRC_FILENAME' "${UPLOAD_SCRIPT}"; then
  echo "ERROR: OBS upload script must upload OBS_RPMLINTRC_FILENAME" >&2
  exit 1
fi
if ! grep -qE '^OBS_RPMLINTRC_FILENAME=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_RPMLINTRC_FILENAME must be set in ${OBS_ENV}" >&2
  exit 1
fi
VERIFY_SCRIPT="${ROOT_DIR}/scripts/obs_upload_verify.py"
if [[ ! -f "${VERIFY_SCRIPT}" ]]; then
  echo "ERROR: missing OBS upload verification helper: ${VERIFY_SCRIPT}" >&2
  exit 1
fi
if ! grep -q -- '--skip-runservice' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must trigger OBS rebuild with --skip-runservice" >&2
  exit 1
fi

WAIT_SCRIPT="${ROOT_DIR}/scripts/obs-wait-for-builds.sh"
if [[ ! -x "${WAIT_SCRIPT}" ]]; then
  echo "ERROR: missing OBS wait script: ${WAIT_SCRIPT}" >&2
  exit 1
fi

if ! grep -q 'obs-wait-for-builds.sh' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must invoke obs-wait-for-builds.sh" >&2
  exit 1
fi

if grep -qE '^OBS_WAIT_REPOSITORIES=.+$' "${OBS_ENV}"; then
  echo "ERROR: OBS_WAIT_REPOSITORIES must not be set in ${OBS_ENV}" >&2
  echo "  enabled repositories are derived from packaging/obs/project/_meta" >&2
  exit 1
fi

if [[ ! -f "${PROJECT_META}" ]]; then
  echo "ERROR: missing OBS project meta file: ${PROJECT_META}" >&2
  exit 1
fi

if [[ ! -x "${SYNC_META_SCRIPT}" ]]; then
  echo "ERROR: missing OBS project meta sync script: ${SYNC_META_SCRIPT}" >&2
  exit 1
fi

if ! grep -q 'sync-obs-project-meta.sh' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must invoke sync-obs-project-meta.sh" >&2
  exit 1
fi

publish_obs_start="$(grep -n '^  publish-obs:' "${RELEASE_WORKFLOW}" | cut -d: -f1)"
wait_obs_start="$(grep -n '^  wait-obs-builds:' "${RELEASE_WORKFLOW}" | cut -d: -f1)"
publish_obs_block="$(sed -n "${publish_obs_start},${wait_obs_start}p" "${RELEASE_WORKFLOW}")"
if ! printf '%s' "${publish_obs_block}" | grep -q 'sync-obs-project-meta.sh'; then
  echo "ERROR: publish-obs job must invoke sync-obs-project-meta.sh" >&2
  exit 1
fi
if ! printf '%s' "${publish_obs_block}" | grep -q -- '--check'; then
  echo "ERROR: publish-obs job must verify project _meta with --check" >&2
  exit 1
fi
if ! printf '%s' "${publish_obs_block}" | grep -q -- '--push'; then
  echo "ERROR: publish-obs job must push project _meta with --push when --check fails" >&2
  exit 1
fi
sync_line="$(printf '%s' "${publish_obs_block}" | grep -n 'sync-obs-project-meta.sh' | head -n1 | cut -d: -f1)"
upload_line="$(printf '%s' "${publish_obs_block}" | grep -n 'obs-upload-release-sources.sh' | head -n1 | cut -d: -f1)"
if [[ -z "${sync_line}" || -z "${upload_line}" || "${sync_line}" -ge "${upload_line}" ]]; then
  echo "ERROR: publish-obs must run sync-obs-project-meta.sh before obs-upload-release-sources.sh" >&2
  exit 1
fi

enabled_repos="$(
  python3 "${REPOSITORIES_HELPER}" --repo-root "${ROOT_DIR}"
)"
if [[ -z "${enabled_repos}" ]]; then
  echo "ERROR: no enabled OBS repositories derived from committed _meta files" >&2
  exit 1
fi

if ! grep -q 'wait-obs-builds' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: release workflow must define wait-obs-builds job" >&2
  exit 1
fi

if ! grep -A3 '^  create-release:' "${RELEASE_WORKFLOW}" | grep -q 'wait-obs-builds'; then
  echo "ERROR: create-release job must depend on wait-obs-builds" >&2
  exit 1
fi

"${ROOT_DIR}/scripts/check-obs-signing.sh" \
  --config "${OBS_ENV}"
