#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Makefile helper: run a leaf check command, optionally via run-check-command.sh.
#
# Usage: scripts/lib/make-run-leaf.sh <label> -- <command...>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=lib/check-quiet-env.sh
source "${SCRIPT_DIR}/check-quiet-env.sh"

[[ $# -ge 1 ]] || exit 2
label=$1
shift
[[ "${1:-}" == "--" ]] || exit 2
shift
[[ $# -ge 1 ]] || exit 2

if vlz_check_brief_enabled; then
  exec "${REPO_ROOT}/scripts/run-check-command.sh" "$label" -- "$@"
fi
exec "$@"
