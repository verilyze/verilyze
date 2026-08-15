#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Download, verify, and extract a versioned platform archive for a GitHub
# Release tag (draft or published). Prints the absolute vlz binary path.
#
# Requires env:
#   VLZ_RELEASE_DOWNLOAD_DIR
#   VLZ_RELEASE_TAG
#   VLZ_RELEASE_PLATFORM -- linux-x86_64, macos-aarch64, or windows-x86_64
#   EXPECTED_BUILDER_REGEX
# Optional:
#   GITHUB_REPOSITORY / GH_REPO
#   GH_TOKEN / GITHUB_TOKEN
#   SLSA_GENERATOR_BUILDER_REGEX

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ci-install-vlz-release-common.sh
source "${ROOT}/scripts/lib/ci-install-vlz-release-common.sh"

: "${VLZ_RELEASE_DOWNLOAD_DIR:?VLZ_RELEASE_DOWNLOAD_DIR is required}"
: "${VLZ_RELEASE_TAG:?VLZ_RELEASE_TAG is required}"
: "${VLZ_RELEASE_PLATFORM:?VLZ_RELEASE_PLATFORM is required}"

REPO="${GITHUB_REPOSITORY:-${GH_REPO:-verilyze/verilyze}}"
TAG="${VLZ_RELEASE_TAG}"
VERSION="$(tag_to_version "${TAG}")"
PLATFORM="${VLZ_RELEASE_PLATFORM}"
ARCHIVE_NAME="$(release_archive_basename "${VERSION}" "${PLATFORM}")"

if [[ ! -d "${VLZ_RELEASE_DOWNLOAD_DIR}" ]]; then
  mkdir -p "${VLZ_RELEASE_DOWNLOAD_DIR}"
fi

patterns=()
while IFS= read -r pattern; do
  patterns+=(--pattern "${pattern}")
done < <(platform_archive_download_patterns "${VERSION}" "${PLATFORM}")

gh release download "${TAG}" \
  --repo "${REPO}" \
  --dir "${VLZ_RELEASE_DOWNLOAD_DIR}" \
  "${patterns[@]}"

if [[ ! -f "${VLZ_RELEASE_DOWNLOAD_DIR}/${ARCHIVE_NAME}" ]]; then
  echo "::error::missing archive ${ARCHIVE_NAME} for ${TAG}" >&2
  exit 1
fi

verify_downloaded_platform_archive \
  "${VLZ_RELEASE_DOWNLOAD_DIR}" \
  "${VERSION}" \
  "${PLATFORM}"

BINARY="$(
  "${ROOT}/scripts/release-extract-platform-archive.sh" \
    --archive "${VLZ_RELEASE_DOWNLOAD_DIR}/${ARCHIVE_NAME}" \
    --platform "${PLATFORM}" \
    --version "${VERSION}" \
    --dest "${VLZ_RELEASE_DOWNLOAD_DIR}/extracted"
)"
chmod +x "${BINARY}"
realpath "${BINARY}"
