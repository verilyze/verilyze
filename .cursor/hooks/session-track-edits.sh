#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Cursor hook: track agent-edited paths for session-scoped validation.
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

mode="${1:-append}"
case "${mode}" in
  clear)
    cursor_hook_python_paths "${repo_root}" "{}" session-clear >/dev/null
    ;;
  append)
    raw_input="$(cursor_hook_read_stdin)"
    cursor_hook_python_paths "${repo_root}" "${raw_input}" session-append >/dev/null
    ;;
  *)
    echo "cursor hook: unknown session-track mode: ${mode}" >&2
    exit 1
    ;;
esac

exit 0
