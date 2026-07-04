#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate coverage badge SVGs from Cobertura when reports exist, otherwise
# write Shields-style unknown badges. Push to the GitHub wiki and exit 1 when
# Cobertura was missing (nightly coverage did not succeed).

set -euo pipefail

_script_dir=$(CDPATH="" cd "$(dirname "$0")" && pwd)
_repo_root=${COVERAGE_BADGE_REPO_ROOT:-"$(CDPATH="" cd "${_script_dir}/.." && pwd)"}

_rust_xml="${_repo_root}/reports/cobertura-rust.xml"
_python_xml="${_repo_root}/reports/cobertura-python.xml"
_rust_svg="${_repo_root}/coverage-rust.svg"
_python_svg="${_repo_root}/coverage-python.svg"

_gen_badge() {
  python3 "${_script_dir}/cobertura_line_badge_svg.py" "$@"
}

if [[ -f "${_rust_xml}" && -f "${_python_xml}" ]]; then
  _gen_badge --label "rust cov" -i "${_rust_xml}" -o "${_rust_svg}"
  _gen_badge --label "python cov" -i "${_python_xml}" -o "${_python_svg}"
  _coverage_ok=1
else
  _gen_badge --label "rust cov" --unknown -o "${_rust_svg}"
  _gen_badge --label "python cov" --unknown -o "${_python_svg}"
  _coverage_ok=0
fi

COVERAGE_BADGE_REPO_ROOT="${_repo_root}" "${_script_dir}/push-coverage-badges-wiki.sh"

if [[ "${_coverage_ok}" -eq 0 ]]; then
  echo "generate-and-push-coverage-badges.sh: published unknown badges (no Cobertura)" >&2
  exit 1
fi
