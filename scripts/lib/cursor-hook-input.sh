# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared helpers for Cursor command hooks.
# Sourced by .cursor/hooks/*.sh; do not execute standalone.
#
# shellcheck shell=bash

cursor_hooks_disabled() {
  case "${VLZ_CURSOR_HOOKS_DISABLE:-}" in
    1 | true | TRUE | yes | YES) return 0 ;;
    *) return 1 ;;
  esac
}

cursor_hook_read_stdin() {
  cat
}

cursor_hook_require_command() {
  local cmd=$1
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "cursor hook: ${cmd} not found; skipping" >&2
    return 1
  fi
  return 0
}

cursor_hook_python_paths() {
  local repo_root=$1
  local raw_input=$2
  local mode=$3
  CURSOR_HOOK_JSON="${raw_input}" PYTHONPATH="${repo_root}${PYTHONPATH:+:${PYTHONPATH}}" \
    python3 - "${mode}" <<'PY'
import json
import os
import sys

from scripts import cursor_validation

mode = sys.argv[1]
payload = os.environ.get("CURSOR_HOOK_JSON", "")
data = cursor_validation.load_hook_json(payload)

if mode == "rust-paths":
    paths = cursor_validation.rust_paths(cursor_validation.parse_edited_paths(data))
    for path in paths:
        print(path)
elif mode == "followup":
    repo = cursor_validation.get_repo_root()
    message = cursor_validation.resolve_stop_followup(data, repo)
    if message:
        print(json.dumps({"followup_message": message}))
elif mode == "session-clear":
    repo = cursor_validation.get_repo_root()
    cursor_validation.clear_session_edit_paths(repo)
elif mode == "session-append":
    repo = cursor_validation.get_repo_root()
    paths = cursor_validation.parse_edited_paths(data)
    if paths:
        cursor_validation.append_session_edit_paths(repo, paths)
else:
    raise SystemExit(f"unknown mode: {mode}")
PY
}
