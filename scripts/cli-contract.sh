#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run the CLI contract suite against an installed or built vlz binary.
# Env:
#   CLI_CONTRACT_BINARY -- path to vlz (optional; built if unset)
#   CLI_CONTRACT_MODE   -- smoke (default) or full

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${CLI_CONTRACT_MODE:-smoke}"
BINARY="${CLI_CONTRACT_BINARY:-}"

if [[ -z "${BINARY}" ]]; then
  (
    cd "${ROOT}"
    cargo build -p vlz --quiet
  )
  target_dir="$(
    cd "${ROOT}"
    cargo metadata --no-deps --format-version 1 \
      | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' \
      | head -1
  )"
  BINARY="${target_dir}/debug/vlz"
  if [[ ! -x "${BINARY}" && -x "${BINARY}.exe" ]]; then
    BINARY="${BINARY}.exe"
  fi
fi

PYTHON="$("${ROOT}/scripts/cli-contract-python.sh")"
PYTHONPATH="${ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONPATH
exec "${PYTHON}" "${ROOT}/scripts/cli_contract.py" \
  --binary "${BINARY}" \
  --mode "${MODE}" \
  --root "${ROOT}"
