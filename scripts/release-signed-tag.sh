#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Create or move a signed SemVer tag and push only that tag (never main).
# Agents should invoke this script (or make release-tag-push / release-tag-move)
# instead of embedding git tag / git push origin v* in the shell command.

set -euo pipefail

usage() {
  echo "usage: $0 push|move <vX.Y.Z> [--dry-run] [--cargo-toml PATH]" >&2
  exit 2
}

MODE=
TAG=
DRY_RUN=0
CARGO_TOML=

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --cargo-toml)
      [[ $# -ge 2 ]] || usage
      CARGO_TOML=$2
      shift 2
      ;;
    push | move)
      [[ -z "${MODE}" ]] || usage
      MODE=$1
      shift
      ;;
    v*)
      [[ -z "${TAG}" ]] || usage
      TAG=$1
      shift
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "${MODE}" && -n "${TAG}" ]] || usage

script_dir="$(cd "$(dirname "$0")" && pwd)"
verify_args=("${TAG}")
if [[ -n "${CARGO_TOML}" ]]; then
  verify_args+=("${CARGO_TOML}")
fi
"${script_dir}/release-verify-tag-version.sh" "${verify_args[@]}" >/dev/null

github_release_not_found() {
  local msg=$1
  [[ "${msg}" == *[Nn]ot\ [Ff]ound* ]] || [[ "${msg}" == *404* ]]
}

# Prints missing, draft, or published. Exits 1 when GitHub cannot be queried.
classify_github_release() {
  local out rc=0
  out="$(gh release view "${TAG}" --json isDraft --jq .isDraft 2>&1)" || rc=$?
  out="${out//$'\r'/}"
  if [[ "${rc}" -eq 0 ]]; then
    case "${out}" in
      false)
        printf '%s\n' published
        return 0
        ;;
      true)
        printf '%s\n' draft
        return 0
        ;;
      *)
        echo "error: unexpected isDraft value for ${TAG}: ${out}" >&2
        exit 1
        ;;
    esac
  fi
  if github_release_not_found "${out}"; then
    printf '%s\n' missing
    return 0
  fi
  printf '%s\n' "${out}" >&2
  echo "error: could not determine GitHub Release state for ${TAG}." >&2
  exit 1
}

refuse_if_published() {
  local state=$1
  if [[ "${state}" == published ]]; then
    echo "error: GitHub Release ${TAG} is not a draft; refuse to ${MODE} the tag." >&2
    exit 1
  fi
}

delete_github_release_idempotent() {
  local err rc=0
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf 'gh release delete %s --yes\n' "${TAG}"
    return 0
  fi
  err="$(gh release delete "${TAG}" --yes 2>&1)" || rc=$?
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi
  if github_release_not_found "${err}"; then
    return 0
  fi
  printf '%s\n' "${err}" >&2
  return "${rc}"
}

delete_remote_tag_idempotent() {
  local err rc=0
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf 'git push origin :refs/tags/%s\n' "${TAG}"
    return 0
  fi
  err="$(git push origin ":refs/tags/${TAG}" 2>&1)" || rc=$?
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${err}" == *"remote ref does not exist"* ]]; then
    return 0
  fi
  printf '%s\n' "${err}" >&2
  return "${rc}"
}

create_and_push() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf 'git tag -s %s -m "Release %s"\n' "${TAG}" "${TAG}"
    printf 'git push origin %s\n' "${TAG}"
    return 0
  fi
  git tag -s "${TAG}" -m "Release ${TAG}"
  git push origin "${TAG}"
}

state="$(classify_github_release)"
refuse_if_published "${state}"

if [[ "${MODE}" == "push" ]]; then
  create_and_push
  exit 0
fi

if [[ "${state}" == draft ]]; then
  delete_github_release_idempotent
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf 'git tag -d %s\n' "${TAG}"
  delete_remote_tag_idempotent
  create_and_push
  exit 0
fi

git tag -d "${TAG}" 2>/dev/null || true
delete_remote_tag_idempotent
create_and_push
