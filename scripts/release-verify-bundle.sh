#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Verify SHA256SUMS and Sigstore bundles for files listed in ARTIFACTS.list.
# Usage: release-verify-bundle.sh <artifact-root-dir>
#
# Environment:
#   EXPECTED_BUILDER_REGEX -- regexp matching the Cosign certificate identity
#                             (GitHub Actions OIDC workflow ref).

set -euo pipefail

readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"

usage() {
  echo "usage: $0 <artifact-root-dir>" >&2
  echo "  EXPECTED_BUILDER_REGEX must be set (certificate identity regexp)." >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

root="$1"
if [[ ! -d "${root}" ]]; then
  echo "::error::artifact root is not a directory: ${root}" >&2
  exit 1
fi

if [[ -z "${EXPECTED_BUILDER_REGEX:-}" ]]; then
  echo "::error::EXPECTED_BUILDER_REGEX is not set" >&2
  exit 1
fi

list_file="${root}/ARTIFACTS.list"
sums_file="${root}/SHA256SUMS"

if [[ ! -f "${list_file}" ]] || [[ ! -s "${list_file}" ]]; then
  echo "::error::missing or empty ARTIFACTS.list under ${root}" >&2
  exit 1
fi

if [[ ! -f "${sums_file}" ]]; then
  echo "::error::missing SHA256SUMS under ${root}" >&2
  exit 1
fi

(
  cd "${root}"
  sha256sum -c SHA256SUMS
)

while IFS= read -r rel_path; do
  [[ -z "${rel_path}" ]] && continue
  file="${root}/${rel_path}"
  if [[ ! -f "${file}" ]]; then
    echo "::error::listed artifact missing: ${rel_path}" >&2
    exit 1
  fi
  if [[ ! -f "${file}.sigstore.json" ]] || [[ ! -s "${file}.sigstore.json" ]]; then
    echo "::error::missing or empty bundle for ${rel_path}: ${file}.sigstore.json" >&2
    exit 1
  fi
  if [[ ! -f "${file}.intoto.jsonl" ]] || [[ ! -s "${file}.intoto.jsonl" ]]; then
    echo "::error::missing or empty attestation bundle for ${rel_path}: ${file}.intoto.jsonl" >&2
    exit 1
  fi

  cosign verify-blob \
    --bundle "${file}.sigstore.json" \
    --certificate-identity-regexp "${EXPECTED_BUILDER_REGEX}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    "${file}"

  cosign verify-blob-attestation \
    --bundle "${file}.intoto.jsonl" \
    --new-bundle-format \
    --type slsaprovenance \
    --certificate-identity-regexp "${EXPECTED_BUILDER_REGEX}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    "${file}"
done < "${list_file}"
