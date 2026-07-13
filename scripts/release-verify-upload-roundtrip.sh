#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Local rehearsal of create-release upload layout and draft re-verify checksums.
# Simulates staging, flat GitHub download names, restore, and SHA256SUMS -c.
# Does not run cosign (release-verify-bundle.sh requires OIDC).
# Usage: release-verify-upload-roundtrip.sh

set -euo pipefail

readonly FIXTURE_DEB="vlz_0.0.0-1_amd64.deb"
readonly FIXTURE_RPM="verilyze-0.0.0-1.fc45.x86_64.rpm"
readonly GITHUB_UPLOAD_PATHS=(
  "release-artifacts/github-upload/vlz-linux-x86_64"
  "release-artifacts/github-upload/vlz-linux-x86_64.sigstore.json"
  "release-artifacts/github-upload/vlz-linux-x86_64.intoto.jsonl"
  "release-artifacts/github-upload/vlz-macos-aarch64"
  "release-artifacts/github-upload/vlz-macos-aarch64.sigstore.json"
  "release-artifacts/github-upload/vlz-macos-aarch64.intoto.jsonl"
  "release-artifacts/github-upload/vlz-windows-x86_64.exe"
  "release-artifacts/github-upload/vlz-windows-x86_64.exe.sigstore.json"
  "release-artifacts/github-upload/vlz-windows-x86_64.exe.intoto.jsonl"
)

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
cd "${root}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

artifacts="${workdir}/release-artifacts"
download_dir="${workdir}/draft-verify"
mkdir -p "${artifacts}/deb-package" "${artifacts}/rpm-package/x86_64"

for rel_path in \
  vlz-linux-x86_64/vlz \
  vlz-macos-aarch64/vlz \
  vlz-windows-x86_64/vlz.exe; do
  path="${artifacts}/${rel_path}"
  mkdir -p "$(dirname "${path}")"
  printf '%s' "${rel_path}" > "${path}"
  printf '{}' > "${path}.sigstore.json"
  printf '{}' > "${path}.intoto.jsonl"
done

printf 'deb' > "${artifacts}/deb-package/${FIXTURE_DEB}"
printf 'rpm' > "${artifacts}/rpm-package/x86_64/${FIXTURE_RPM}"

./scripts/release-generate-checksums.sh "${artifacts}" >/dev/null
./scripts/release-stage-github-binary-upload.sh "${artifacts}"

for rel_path in "${GITHUB_UPLOAD_PATHS[@]}"; do
  if [[ ! -f "${workdir}/${rel_path}" ]]; then
    echo "error: missing staged upload path: ${rel_path}" >&2
    exit 1
  fi
done

mkdir -p "${download_dir}"
cp -a "${artifacts}/github-upload/." "${download_dir}/"
cp -a "${artifacts}/deb-package/." "${download_dir}/"
cp -a "${artifacts}/rpm-package/x86_64/." "${download_dir}/"
cp -f "${artifacts}/SHA256SUMS" "${download_dir}/SHA256SUMS"

./scripts/release-restore-download-layout.sh "${download_dir}"

(
  cd "${download_dir}"
  sha256sum -c SHA256SUMS
)

echo "release-verify-upload-roundtrip: OK (layout and SHA256SUMS round-trip)"
