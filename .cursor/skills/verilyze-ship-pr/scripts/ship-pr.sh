#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Allowlisted helper for verilyze-ship-pr remote writes.
# Agents must invoke this script instead of embedding git push /
# gh pr create / gh pr merge in the Shell command string so Cursor
# Auto-run can allowlist one stable path.

set -euo pipefail

readonly DEFAULT_BRANCH="${VLZ_SHIP_PR_BASE_BRANCH:-main}"
readonly MERGE_POLL_MAX="${VLZ_SHIP_PR_MERGE_POLL_MAX:-90}"
readonly MERGE_POLL_SLEEP="${VLZ_SHIP_PR_MERGE_POLL_SLEEP:-2}"

usage() {
  cat >&2 <<'USAGE'
usage:
  ship-pr.sh push
  ship-pr.sh force-push [origin/<branch>:<sha>]
  ship-pr.sh merge
  ship-pr.sh create-pr --title <title> --body-file <path>
USAGE
  exit 2
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_git_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || die "not inside a git work tree"
}

enter_git_toplevel() {
  require_git_repo
  cd "$(git rev-parse --show-toplevel)"
}

require_not_main_branch() {
  local branch=""
  branch="$(git branch --show-current)"
  if [[ -z "${branch}" ]]; then
    die "detached HEAD; checkout a feature branch before ship remote writes"
  fi
  if [[ "${branch}" == "${DEFAULT_BRANCH}" ]]; then
    die "refusing remote write on ${DEFAULT_BRANCH}; create a feature branch first"
  fi
}

prepare_git_context() {
  enter_git_toplevel
  require_not_main_branch
}

require_open_pr() {
  local state=""
  if ! state="$(gh pr view --json state --jq .state 2>/dev/null)"; then
    die "no open PR for current branch; open a PR before merge"
  fi
  if [[ "${state}" == "MERGED" ]]; then
    die "PR already merged"
  fi
}

cmd_push() {
  prepare_git_context
  git push -u origin HEAD
}

cmd_force_push() {
  prepare_git_context
  local lease="${1:-}"
  if [[ -n "${lease}" ]]; then
    git push --force-with-lease="${lease}" origin HEAD
  else
    git push --force-with-lease
  fi
}

cmd_merge() {
  prepare_git_context
  require_open_pr
  local state=""
  gh pr merge --merge --admin
  for _ in $(seq 1 "${MERGE_POLL_MAX}"); do
    state="$(gh pr view --json state --jq .state 2>/dev/null || true)"
    if [[ "${state}" == "MERGED" ]]; then
      gh pr view --json state,mergedAt
      return 0
    fi
    sleep "${MERGE_POLL_SLEEP}"
  done
  die "PR state is '${state:-unknown}' after merge; expected MERGED"
}

cmd_create_pr() {
  prepare_git_context
  local title="" body_file=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --title)
        [[ $# -ge 2 ]] || usage
        title=$2
        shift 2
        ;;
      --body-file)
        [[ $# -ge 2 ]] || usage
        body_file=$2
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done
  [[ -n "${title}" && -n "${body_file}" ]] || usage
  [[ -f "${body_file}" ]] || die "body file not found: ${body_file}"
  gh pr create --base "${DEFAULT_BRANCH}" --title "${title}" --body-file "${body_file}"
}

MODE="${1:-}"
[[ -n "${MODE}" ]] || usage
shift || true

case "${MODE}" in
  push)
    [[ $# -eq 0 ]] || usage
    cmd_push
    ;;
  force-push)
    [[ $# -le 1 ]] || usage
    cmd_force_push "${1:-}"
    ;;
  merge)
    [[ $# -eq 0 ]] || usage
    cmd_merge
    ;;
  create-pr)
    cmd_create_pr "$@"
    ;;
  *)
    usage
    ;;
esac
