# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared helpers for ci-install-vlz-release.sh (SEC-015 nightly release binary).
#
# shellcheck shell=bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-artifact-names.sh
source "${script_dir}/release-artifact-names.sh"

readonly RELEASE_OIDC_ISSUER="https://token.actions.githubusercontent.com"

readonly SLSA_GENERATOR_PIN_SHA='f7dd8c54c2067bafc12ca7a55595d5ee9b75204a'
readonly SLSA_GENERATOR_BUILDER_REGEX_DEFAULT="^https://github\\.com/slsa-framework/slsa-github-generator/\\.github/workflows/generator_generic_slsa3\\.yml@(v2\\.1\\.0|${SLSA_GENERATOR_PIN_SHA})\$"

# Legacy raw GitHub asset names (v0.4.0 through last non-archive release).
# Remove once the oldest supported release publishes versioned archives.
readonly LEGACY_LINUX_FLAT_ASSET_NAME="vlz-linux-x86_64"
readonly LEGACY_LINUX_FLAT_ASSET_NAME_V031="vlz"
readonly LEGACY_LINUX_BINARY_REL_PATH="vlz-linux-x86_64/vlz"

tag_to_version() {
  local tag="${1:?tag required}"
  # Strip a single leading v from Git tags (v1.2.3 -> 1.2.3).
  printf '%s' "${tag#v}"
}
linux_archive_basename_for_version() {
  local version="${1:?version required}"
  release_archive_basename "${version}" "linux-x86_64"
}

linux_archive_download_patterns() {
  local version="${1:?version required}"
  local archive
  archive="$(linux_archive_basename_for_version "${version}")"
  printf '%s\n' \
    'SHA256SUMS' \
    "${archive}" \
    "${archive}.sigstore.json" \
    "${archive}.intoto.jsonl"
}

# Patterns for older releases that published raw platform binaries.
# Drop when the oldest supported release is archive-based.
legacy_linux_release_download_patterns() {
  printf '%s\n' \
    'SHA256SUMS' \
    "${LEGACY_LINUX_FLAT_ASSET_NAME}" \
    "${LEGACY_LINUX_FLAT_ASSET_NAME}.sigstore.json" \
    "${LEGACY_LINUX_FLAT_ASSET_NAME}.intoto.jsonl" \
    "${LEGACY_LINUX_FLAT_ASSET_NAME_V031}" \
    "${LEGACY_LINUX_FLAT_ASSET_NAME_V031}.sigstore.json" \
    "${LEGACY_LINUX_FLAT_ASSET_NAME_V031}.intoto.jsonl"
}

verify_blob_attestation_with_builder_fallback() {
  local file="${1:?binary path required}"
  local bundle="${2:?attestation bundle path required}"
  local release_regex="${3:?release builder regex required}"
  local slsa_regex="${4:?slsa builder regex required}"

  if cosign verify-blob-attestation \
    --bundle "${bundle}" \
    --new-bundle-format \
    --type slsaprovenance \
    --certificate-identity-regexp "${slsa_regex}" \
    --certificate-oidc-issuer "${RELEASE_OIDC_ISSUER}" \
    "${file}" >&2; then
    return 0
  fi

  cosign verify-blob-attestation \
    --bundle "${bundle}" \
    --new-bundle-format \
    --type slsaprovenance \
    --certificate-identity-regexp "${release_regex}" \
    --certificate-oidc-issuer "${RELEASE_OIDC_ISSUER}" \
    "${file}" >&2
}

resolve_latest_release_tag() {
  local repo="${1:?repository required}"
  local tag
  tag="$(
    gh release list \
      --repo "${repo}" \
      --exclude-drafts \
      --exclude-pre-releases \
      -L 1 \
      --json tagName \
      -q '.[0].tagName' 2>/dev/null || true
  )"
  if [[ -z "${tag}" ]]; then
    echo "::error::no non-draft, non-prerelease GitHub release found for ${repo}" >&2
    return 1
  fi
  printf '%s' "${tag}"
}

verify_release_asset() {
  local root="${1:?artifact root required}"
  local rel_path="${2:?relative asset path required}"
  local file="${root}/${rel_path}"
  local sums_file="${root}/SHA256SUMS"
  local builder_regex="${EXPECTED_BUILDER_REGEX:?EXPECTED_BUILDER_REGEX is required}"
  local slsa_regex="${SLSA_GENERATOR_BUILDER_REGEX:-${SLSA_GENERATOR_BUILDER_REGEX_DEFAULT}}"

  if [[ ! -f "${file}" ]]; then
    echo "::error::missing release asset: ${rel_path}" >&2
    return 1
  fi
  if [[ ! -f "${sums_file}" ]]; then
    echo "::error::missing SHA256SUMS under ${root}" >&2
    return 1
  fi
  if [[ ! -f "${file}.sigstore.json" ]] || [[ ! -s "${file}.sigstore.json" ]]; then
    echo "::error::missing or empty bundle: ${rel_path}.sigstore.json" >&2
    return 1
  fi
  if [[ ! -f "${file}.intoto.jsonl" ]] || [[ ! -s "${file}.intoto.jsonl" ]]; then
    echo "::error::missing or empty attestation: ${rel_path}.intoto.jsonl" >&2
    return 1
  fi

  (
    cd "${root}" || exit 1
    grep -F "${rel_path}" SHA256SUMS | sha256sum -c >&2
  )

  cosign verify-blob \
    --bundle "${file}.sigstore.json" \
    --certificate-identity-regexp "${builder_regex}" \
    --certificate-oidc-issuer "${RELEASE_OIDC_ISSUER}" \
    "${file}" >&2

  verify_blob_attestation_with_builder_fallback \
    "${file}" \
    "${file}.intoto.jsonl" \
    "${builder_regex}" \
    "${slsa_regex}"
}

verify_downloaded_linux_archive() {
  local root="${1:?artifact root required}"
  local version="${2:?version required}"
  local archive
  archive="$(linux_archive_basename_for_version "${version}")"
  verify_release_asset "${root}" "${archive}"
}

# Legacy path for raw platform binaries (pre-archive releases).
verify_downloaded_linux_binary() {
  local root="${1:?artifact root required}"
  local rel_path="${LEGACY_LINUX_BINARY_REL_PATH}"
  verify_release_asset "${root}" "${rel_path}"
}
