#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Copy coverage-*.svg from the repository root into the GitHub wiki repo and
# push. Requires GITHUB_TOKEN with permission to update the wiki, and
# COVERAGE_BADGE_REPO_ROOT pointing at the checked-out main repo (default: ..).
#
# One-time: enable the repository wiki and create an initial page so the wiki
# git remote exists.

set -euo pipefail

_script_dir=$(CDPATH="" cd "$(dirname "$0")" && pwd)
_repo_root=${COVERAGE_BADGE_REPO_ROOT:-"$(CDPATH="" cd "${_script_dir}/.." && pwd)"}

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "push-coverage-badges-wiki.sh: GITHUB_TOKEN is not set" >&2
  exit 1
fi

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "push-coverage-badges-wiki.sh: GITHUB_REPOSITORY is not set" >&2
  exit 1
fi

for _f in coverage-rust.svg coverage-python.svg; do
  if [[ ! -f "${_repo_root}/${_f}" ]]; then
    echo "push-coverage-badges-wiki.sh: missing ${_repo_root}/${_f}" >&2
    exit 1
  fi
done

_work=$(mktemp -d)
trap 'rm -rf "${_work}"' EXIT

_git_url="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.wiki.git"

git clone --depth=1 "${_git_url}" "${_work}/wiki"

cd "${_work}/wiki"

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

cp -f "${_repo_root}/coverage-rust.svg" "${_repo_root}/coverage-python.svg" .

git add coverage-rust.svg coverage-python.svg

if git diff --staged --quiet; then
  echo "Wiki badges unchanged; skipping commit."
  exit 0
fi

git commit -m "Update coverage badges (nightly workflow)"

git push origin HEAD
