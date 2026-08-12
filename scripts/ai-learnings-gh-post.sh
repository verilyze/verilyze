#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Post AI learnings evidence only after gitleaks preflight.
# Prefer this over raw `gh` for issue create/comment and PR comments.
#
# Usage:
#   ai-learnings-gh-post.sh issue-create --title T --body-file F \
#     [--label ai-learnings]
#   ai-learnings-gh-post.sh issue-comment <number> --body-file F
#   ai-learnings-gh-post.sh pr-comment <number> --body-file F
#
# Body file is always removed on EXIT when --body-file points at a path
# under the process temp dir created by this script (see --stdin).
# Caller-owned --body-file paths are left in place unless --rm-body is set.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFLIGHT="${ROOT_DIR}/scripts/ai-learnings-gitleaks-preflight.sh"

BODY_FILE=
RM_BODY=0
OWNED_BODY=0
TITLE=
LABEL="ai-learnings"
NUMBER=
CMD=

trap 'if [[ "${OWNED_BODY}" -eq 1 && -n "${BODY_FILE}" && -f "${BODY_FILE}" ]]; then rm -f "${BODY_FILE}"; fi' EXIT

usage() {
  cat >&2 <<'EOF'
Usage:
  ai-learnings-gh-post.sh issue-create --title T --body-file F [--label L]
  ai-learnings-gh-post.sh issue-create --title T --stdin [--label L]
  ai-learnings-gh-post.sh issue-comment <n> --body-file F [--rm-body]
  ai-learnings-gh-post.sh issue-comment <n> --stdin
  ai-learnings-gh-post.sh pr-comment <n> --body-file F [--rm-body]
  ai-learnings-gh-post.sh pr-comment <n> --stdin

Runs gitleaks preflight, then gh. --stdin writes a temp body and deletes it
on EXIT. --rm-body deletes a caller --body-file after a successful post.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 2
}

require_gh() {
  if ! command -v gh >/dev/null 2>&1; then
    die "gh is required"
  fi
}

absorb_stdin() {
  BODY_FILE="$(mktemp)"
  OWNED_BODY=1
  cat >"${BODY_FILE}"
}

parse_body_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --body-file)
        [[ $# -ge 2 ]] || die "--body-file needs a path"
        BODY_FILE=$2
        shift 2
        ;;
      --stdin)
        absorb_stdin
        shift
        ;;
      --rm-body)
        RM_BODY=1
        shift
        ;;
      --title)
        [[ $# -ge 2 ]] || die "--title needs a value"
        TITLE=$2
        shift 2
        ;;
      --label)
        [[ $# -ge 2 ]] || die "--label needs a value"
        LABEL=$2
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

run_preflight() {
  [[ -n "${BODY_FILE}" && -f "${BODY_FILE}" ]] ||
    die "body required (--body-file or --stdin)"
  "${PREFLIGHT}" "${BODY_FILE}"
}

maybe_rm_caller_body() {
  if [[ "${RM_BODY}" -eq 1 && "${OWNED_BODY}" -eq 0 && -f "${BODY_FILE}" ]]; then
    rm -f "${BODY_FILE}"
  fi
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

CMD=$1
shift

case "${CMD}" in
  issue-create)
    parse_body_args "$@"
    [[ -n "${TITLE}" ]] || die "issue-create requires --title"
    require_gh
    run_preflight
    gh issue create --title "${TITLE}" --label "${LABEL}" \
      --body-file "${BODY_FILE}"
    maybe_rm_caller_body
    ;;
  issue-comment)
    [[ $# -ge 1 ]] || die "issue-comment requires an issue number"
    NUMBER=$1
    shift
    parse_body_args "$@"
    require_gh
    run_preflight
    gh issue comment "${NUMBER}" --body-file "${BODY_FILE}"
    maybe_rm_caller_body
    ;;
  pr-comment)
    [[ $# -ge 1 ]] || die "pr-comment requires a PR number"
    NUMBER=$1
    shift
    parse_body_args "$@"
    require_gh
    run_preflight
    gh pr comment "${NUMBER}" --body-file "${BODY_FILE}"
    maybe_rm_caller_body
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage
    die "unknown command: ${CMD}"
    ;;
esac
