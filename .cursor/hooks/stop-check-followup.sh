#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Cursor stop hook: suggest scoped make targets from git diff.
set -euo pipefail

hook_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${hook_dir}/../.." && pwd)"
# shellcheck source=../../scripts/lib/cursor-hook-input.sh
. "${repo_root}/scripts/lib/cursor-hook-input.sh"

if cursor_hooks_disabled; then
  exit 0
fi

if ! cursor_hook_require_command python3; then
  exit 0
fi
if ! cursor_hook_require_command git; then
  exit 0
fi

raw_input="$(cursor_hook_read_stdin)"
followup="$(
  cursor_hook_python_paths "${repo_root}" "${raw_input}" followup 2>/dev/null || true
)"

if [[ -n "${followup}" ]]; then
  printf '%s\n' "${followup}"
fi

exit 0
