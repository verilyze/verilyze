#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Download and verify the latest stable Linux vlz release for SEC-015 nightly CI.
# Prints the absolute path to stdout (workflow sets VLZ_BIN from this output).
#
# Requires env:
#   VLZ_RELEASE_DOWNLOAD_DIR -- directory for gh release download + restore layout
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

gh release download "${TAG}" \
  --repo "${REPO}" \
  --dir "${VLZ_RELEASE_DOWNLOAD_DIR}" \
  --pattern 'vlz' \
  --pattern 'vlz.sigstore.json' \
  --pattern 'vlz.intoto.jsonl' \
  --pattern 'SHA256SUMS'

"${ROOT}/scripts/release-restore-download-layout.sh" "${VLZ_RELEASE_DOWNLOAD_DIR}"

verify_downloaded_linux_binary "${VLZ_RELEASE_DOWNLOAD_DIR}"

BINARY="${VLZ_RELEASE_DOWNLOAD_DIR}/${LINUX_BINARY_REL_PATH}"
chmod +x "${BINARY}"
realpath "${BINARY}"
