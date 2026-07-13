# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared helpers for ci-install-vlz-release.sh (SEC-015 nightly release binary).
#
# shellcheck shell=bash

# Logical path in SHA256SUMS after release-restore-download-layout.sh.
readonly LINUX_BINARY_REL_PATH="vlz-linux-x86_64/vlz"

readonly RELEASE_OIDC_ISSUER="https://token.actions.githubusercontent.com"

readonly SLSA_GENERATOR_PIN_SHA='f7dd8c54c2067bafc12ca7a55595d5ee9b75204a'
readonly SLSA_GENERATOR_BUILDER_REGEX_DEFAULT="^https://github\\.com/slsa-framework/slsa-github-generator/\\.github/workflows/generator_generic_slsa3\\.yml@(v2\\.1\\.0|${SLSA_GENERATOR_PIN_SHA})\$"

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

verify_downloaded_linux_binary() {
  local root="${1:?artifact root required}"
  local rel_path="${LINUX_BINARY_REL_PATH}"
  local file="${root}/${rel_path}"
  local sums_file="${root}/SHA256SUMS"
  local builder_regex="${EXPECTED_BUILDER_REGEX:?EXPECTED_BUILDER_REGEX is required}"
  local slsa_regex="${SLSA_GENERATOR_BUILDER_REGEX:-${SLSA_GENERATOR_BUILDER_REGEX_DEFAULT}}"

  if [[ ! -f "${file}" ]]; then
    echo "::error::missing Linux release binary: ${rel_path}" >&2
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

  # sha256sum -c and cosign write status to stdout; install script prints only the
  # binary path on stdout for GITHUB_ENV capture.
  (
    cd "${root}" || exit 1
    grep -F "${rel_path}" SHA256SUMS | sha256sum -c >&2
  )

  cosign verify-blob \
    --bundle "${file}.sigstore.json" \
    --certificate-identity-regexp "${builder_regex}" \
    --certificate-oidc-issuer "${RELEASE_OIDC_ISSUER}" \
    "${file}" >&2

  # Published Linux binaries may carry SLSA generator attestations (current
  # releases) or release.yml attestations (legacy v0.3.1-style assets).
  verify_blob_attestation_with_builder_fallback \
    "${file}" \
    "${file}.intoto.jsonl" \
    "${builder_regex}" \
    "${slsa_regex}"
}
