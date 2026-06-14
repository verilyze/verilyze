#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Cursor afterFileEdit hook: format agent-edited Rust files only.
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
if ! cursor_hook_require_command cargo; then
  exit 0
fi

raw_input="$(cursor_hook_read_stdin)"
mapfile -t rust_paths < <(
  cursor_hook_python_paths "${repo_root}" "${raw_input}" rust-paths 2>/dev/null || true
)

if ((${#rust_paths[@]} == 0)); then
  exit 0
fi

cd "${repo_root}"
if ! cargo fmt -- "${rust_paths[@]}" 2>/dev/null; then
  for path in "${rust_paths[@]}"; do
    if [[ -f "${path}" ]] && command -v rustfmt >/dev/null 2>&1; then
      rustfmt "${path}" 2>/dev/null || true
    fi
  done
fi

exit 0
