#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate coverage badge SVGs from Cobertura when the coverage step succeeded
# and both reports exist; otherwise write Shields-style unknown badges. Push to
# the GitHub wiki and exit 1 when badges are unknown (failed or incomplete run).
#
# Env:
#   COVERAGE_BADGE_REPO_ROOT  -- repo root (default: parent of scripts/)
#   COVERAGE_STEP_OUTCOME     -- GHA steps.coverage.outcome; defaults to success
#                                locally (trusts Cobertura on disk)
#   COVERAGE_BADGE_SKIP_PUSH  -- set to 1 to skip wiki push (tests only)

set -euo pipefail

_script_dir=$(CDPATH="" cd "$(dirname "$0")" && pwd)
_repo_root=${COVERAGE_BADGE_REPO_ROOT:-"$(CDPATH="" cd "${_script_dir}/.." && pwd)"}

_rust_xml="${_repo_root}/reports/cobertura-rust.xml"
_python_xml="${_repo_root}/reports/cobertura-python.xml"
_rust_svg="${_repo_root}/coverage-rust.svg"
_python_svg="${_repo_root}/coverage-python.svg"
_coverage_outcome="${COVERAGE_STEP_OUTCOME:-success}"

_gen_badge() {
  python3 "${_script_dir}/cobertura_line_badge_svg.py" "$@"
}

_has_rust=0
_has_python=0
[[ -f "${_rust_xml}" ]] && _has_rust=1
[[ -f "${_python_xml}" ]] && _has_python=1

if [[ "${_coverage_outcome}" == "success" \
  && "${_has_rust}" -eq 1 && "${_has_python}" -eq 1 ]]; then
  _gen_badge --label "rust cov" -i "${_rust_xml}" -o "${_rust_svg}"
  _gen_badge --label "python cov" -i "${_python_xml}" -o "${_python_svg}"
  _coverage_ok=1
else
  _gen_badge --label "rust cov" --unknown -o "${_rust_svg}"
  _gen_badge --label "python cov" --unknown -o "${_python_svg}"
  _coverage_ok=0
fi

if [[ "${COVERAGE_BADGE_SKIP_PUSH:-0}" != "1" ]]; then
  COVERAGE_BADGE_REPO_ROOT="${_repo_root}" "${_script_dir}/push-coverage-badges-wiki.sh"
fi

if [[ "${_coverage_ok}" -eq 0 ]]; then
  _reasons=()
  if [[ "${_coverage_outcome}" != "success" ]]; then
    _reasons+=("coverage step did not succeed")
  fi
  if [[ "${_has_rust}" -eq 0 || "${_has_python}" -eq 0 ]]; then
    _reasons+=("incomplete Cobertura reports")
  fi
  _joined="${_reasons[0]}"
  if ((${#_reasons[@]} > 1)); then
    _joined="${_reasons[0]}; ${_reasons[1]}"
  fi
  echo "generate-and-push-coverage-badges.sh: published unknown badges (${_joined})" >&2
  exit 1
fi
