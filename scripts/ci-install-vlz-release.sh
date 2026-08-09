#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Download and verify the latest stable Linux vlz release for SEC-015 nightly CI.
# Prints the absolute path to stdout (workflow sets VLZ_BIN from this output).
#
# Requires env:
#   VLZ_RELEASE_DOWNLOAD_DIR -- directory for gh release download + extract
#   EXPECTED_BUILDER_REGEX   -- Cosign certificate identity (release.yml parity)
# Optional:
#   GITHUB_REPOSITORY / GH_REPO -- default verilyze/verilyze
#   GH_TOKEN / GITHUB_TOKEN
#   SLSA_GENERATOR_BUILDER_REGEX

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ci-install-vlz-release-common.sh
source "${ROOT}/scripts/lib/ci-install-vlz-release-common.sh"

: "${VLZ_RELEASE_DOWNLOAD_DIR:?VLZ_RELEASE_DOWNLOAD_DIR is required}"

REPO="${GITHUB_REPOSITORY:-${GH_REPO:-verilyze/verilyze}}"

if [[ ! -d "${VLZ_RELEASE_DOWNLOAD_DIR}" ]]; then
  mkdir -p "${VLZ_RELEASE_DOWNLOAD_DIR}"
fi

TAG="$(resolve_latest_release_tag "${REPO}")"
VERSION="$(tag_to_version "${TAG}")"
ARCHIVE_NAME="$(linux_archive_basename_for_version "${VERSION}")"

download_with_patterns() {
  local -a patterns=()
  while IFS= read -r pattern; do
    patterns+=(--pattern "${pattern}")
  done
  gh release download "${TAG}" \
    --repo "${REPO}" \
    --dir "${VLZ_RELEASE_DOWNLOAD_DIR}" \
    "${patterns[@]}"
}

# Prefer versioned platform archives (current releases).
download_with_patterns < <(linux_archive_download_patterns "${VERSION}")

if [[ -f "${VLZ_RELEASE_DOWNLOAD_DIR}/${ARCHIVE_NAME}" ]]; then
  verify_downloaded_linux_archive "${VLZ_RELEASE_DOWNLOAD_DIR}" "${VERSION}"
  BINARY="$(
    "${ROOT}/scripts/release-extract-platform-archive.sh" \
      --archive "${VLZ_RELEASE_DOWNLOAD_DIR}/${ARCHIVE_NAME}" \
      --platform linux-x86_64 \
      --version "${VERSION}" \
      --dest "${VLZ_RELEASE_DOWNLOAD_DIR}/extracted"
  )"
  chmod +x "${BINARY}"
  realpath "${BINARY}"
  exit 0
fi

# Legacy: raw platform-qualified or bare `vlz` assets from older tags.
# Remove once the oldest supported release publishes archives.
echo "::warning::archive ${ARCHIVE_NAME} not found; trying legacy raw assets" >&2
download_with_patterns < <(legacy_linux_release_download_patterns)

"${ROOT}/scripts/release-restore-download-layout.sh" "${VLZ_RELEASE_DOWNLOAD_DIR}"
verify_downloaded_linux_binary "${VLZ_RELEASE_DOWNLOAD_DIR}"

BINARY="${VLZ_RELEASE_DOWNLOAD_DIR}/${LEGACY_LINUX_BINARY_REL_PATH}"
chmod +x "${BINARY}"
realpath "${BINARY}"
