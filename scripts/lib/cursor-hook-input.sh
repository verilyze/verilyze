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
    import subprocess

    repo = cursor_validation.get_repo_root()
    diff_paths: list[str] = []
    for cmd in (
        ["git", "diff", "--name-only"],
        ["git", "diff", "--cached", "--name-only"],
    ):
        proc = subprocess.run(
            cmd,
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            diff_paths.extend(proc.stdout.splitlines())
    diff_paths = list(dict.fromkeys(diff_paths))
    targets = cursor_validation.classify_changed_paths(diff_paths)
    if cursor_validation.should_skip_followup(data, targets):
        sys.exit(0)
    message = cursor_validation.build_followup_message(targets)
    print(json.dumps({"followup_message": message}))
else:
    raise SystemExit(f"unknown mode: {mode}")
PY
}
