#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate shell completions (bash, zsh, fish) from the vlz binary.
# Usage: scripts/generate_completions.sh <path-to-vlz-binary>
#
# Run from repository root. Creates completions/ in the current directory.

set -euo pipefail

BIN="${1:?Usage: $0 <path-to-vlz-binary>}"
mkdir -p completions

write_completion() {
  local shell_name="$1"
  local target_path="$2"
  local tmp_path
  tmp_path="$(mktemp "${target_path}.tmp.XXXXXX")"
  trap 'rm -f "$tmp_path"' RETURN
  "$BIN" generate-completions "$shell_name" > "$tmp_path"
  mv -f "$tmp_path" "$target_path"
  trap - RETURN
}

write_completion bash completions/vlz.bash
write_completion zsh completions/_vlz
write_completion fish completions/vlz.fish
