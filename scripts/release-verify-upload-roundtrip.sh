#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Local rehearsal of create-release staging and SHA256SUMS -c without restore.
# Builds real platform archives via release-build-platform-archive.sh.
# Does not run cosign (release-verify-bundle.sh requires OIDC).
# Usage: release-verify-upload-roundtrip.sh

set -euo pipefail

readonly FIXTURE_DEB="vlz_0.0.0-1_amd64.deb"
readonly FIXTURE_RPM="verilyze-0.0.0-1.fc45.x86_64.rpm"
readonly FIXTURE_VERSION="0.0.0"

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
cd "${root}"

# shellcheck source=lib/release-artifact-names.sh
source "${root}/scripts/lib/release-artifact-names.sh"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

artifacts="${workdir}/release-artifacts"
download_dir="${workdir}/draft-verify"
mkdir -p "${artifacts}/deb-package" "${artifacts}/rpm-package/x86_64"

# Fake binaries for archive members.
fake_bin="${workdir}/vlz"
fake_exe="${workdir}/vlz.exe"
printf 'linux-bin' > "${fake_bin}"
chmod 755 "${fake_bin}"
printf 'windows-bin' > "${fake_exe}"

for platform in "${RELEASE_PLATFORMS[@]}"; do
  actions_name="$(release_actions_artifact_name "${platform}")"
  out_dir="${artifacts}/${actions_name}"
  mkdir -p "${out_dir}"
  if release_is_windows_platform "${platform}"; then
    bin_path="${fake_exe}"
  else
    bin_path="${fake_bin}"
  fi
  ./scripts/release-build-platform-archive.sh \
    --platform "${platform}" \
    --version "${FIXTURE_VERSION}" \
    --binary "${bin_path}" \
    --repo-root "${root}" \
    --output-dir "${out_dir}" >/dev/null
  archive_name="$(release_archive_basename "${FIXTURE_VERSION}" "${platform}")"
  printf '{}' > "${out_dir}/${archive_name}.sigstore.json"
  printf '{}' > "${out_dir}/${archive_name}.intoto.jsonl"
done

printf 'deb' > "${artifacts}/deb-package/${FIXTURE_DEB}"
printf '{}' > "${artifacts}/deb-package/${FIXTURE_DEB}.sigstore.json"
printf '{}' > "${artifacts}/deb-package/${FIXTURE_DEB}.intoto.jsonl"
printf 'rpm' > "${artifacts}/rpm-package/x86_64/${FIXTURE_RPM}"
printf '{}' > "${artifacts}/rpm-package/x86_64/${FIXTURE_RPM}.sigstore.json"
printf '{}' > "${artifacts}/rpm-package/x86_64/${FIXTURE_RPM}.intoto.jsonl"

./scripts/release-stage-github-upload.sh "${artifacts}" "${FIXTURE_VERSION}"
upload_dir="${artifacts}/github-upload"

./scripts/release-generate-checksums.sh "${upload_dir}" >/dev/null

expected_names=(
  "$(release_archive_basename "${FIXTURE_VERSION}" linux-x86_64)"
  "$(release_archive_basename "${FIXTURE_VERSION}" macos-aarch64)"
  "$(release_archive_basename "${FIXTURE_VERSION}" windows-x86_64)"
  "${FIXTURE_DEB}"
  "${FIXTURE_RPM}"
)
for name in "${expected_names[@]}"; do
  if [[ ! -f "${upload_dir}/${name}" ]]; then
    echo "error: missing staged upload path: ${name}" >&2
    exit 1
  fi
done

mkdir -p "${download_dir}"
cp -a "${upload_dir}/." "${download_dir}/"

(
  cd "${download_dir}"
  sha256sum -c SHA256SUMS
)

# Extract each archive and assert layout / executable path.
extract_root="${workdir}/extract"
for platform in "${RELEASE_PLATFORMS[@]}"; do
  archive_name="$(release_archive_basename "${FIXTURE_VERSION}" "${platform}")"
  ./scripts/release-extract-platform-archive.sh \
    --archive "${download_dir}/${archive_name}" \
    --platform "${platform}" \
    --version "${FIXTURE_VERSION}" \
    --dest "${extract_root}/${platform}" >/dev/null
done

echo "release-verify-upload-roundtrip: OK (archive layout and SHA256SUMS round-trip)"
