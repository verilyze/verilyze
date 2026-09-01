#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Post AI learnings evidence only after gitleaks preflight.
# Prefer this over raw `gh` for issue create/comment and PR comments.
#
# Usage:
#   ai-learnings-gh-post.sh issue-create --title T --body-file F
#   ai-learnings-gh-post.sh issue-comment <number> --body-file F
#   ai-learnings-gh-post.sh pr-comment <number> --body-file F
#
# issue-create always sets GitHub Issue Type Learning (org type) and label
# ai-learnings. Do not invent alternate type or label names.
#
# Body file is always removed on EXIT when --body-file points at a path
# under the process temp dir created by this script (see --stdin).
# Caller-owned --body-file paths are left in place unless --rm-body is set.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFLIGHT="${ROOT_DIR}/scripts/ai-learnings-gitleaks-preflight.sh"

# Keep in sync with org Issue Type name and docs in ai-learnings.md.
readonly AI_LEARNINGS_LABEL="ai-learnings"
readonly AI_LEARNINGS_ISSUE_TYPE="Learning"

BODY_FILE=
RM_BODY=0
OWNED_BODY=0
TITLE=
NUMBER=
CMD=

trap 'if [[ "${OWNED_BODY}" -eq 1 && -n "${BODY_FILE}" && -f "${BODY_FILE}" ]]; then rm -f "${BODY_FILE}"; fi' EXIT

usage() {
  cat >&2 <<'EOF'
Usage:
  ai-learnings-gh-post.sh issue-create --title T --body-file F
  ai-learnings-gh-post.sh issue-create --title T --stdin
  ai-learnings-gh-post.sh issue-comment <n> --body-file F [--rm-body]
  ai-learnings-gh-post.sh issue-comment <n> --stdin
  ai-learnings-gh-post.sh pr-comment <n> --body-file F [--rm-body]
  ai-learnings-gh-post.sh pr-comment <n> --stdin

Runs gitleaks preflight, then gh. issue-create always sets --type Learning
and --label ai-learnings (not overridable). --stdin writes a temp body and
deletes it on EXIT. --rm-body deletes a caller --body-file after a successful
post.
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
        die "--label is not supported; issue-create always uses '${AI_LEARNINGS_LABEL}'"
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

issue_has_label() {
  local issue_num=$1
  local result
  local gh_status=0
  result=$(
    gh issue view "${issue_num}" --json labels \
      --jq "any(.labels[]; .name == \"${AI_LEARNINGS_LABEL}\")"
  ) || gh_status=$?
  if [[ "${gh_status}" -ne 0 ]]; then
    die "gh issue view #${issue_num} failed (labels)"
  fi
  [[ "${result}" == "true" ]]
}

issue_has_type() {
  local issue_num=$1
  local result
  local gh_status=0
  result=$(
    gh issue view "${issue_num}" --json issueType \
      --jq ".issueType.name == \"${AI_LEARNINGS_ISSUE_TYPE}\""
  ) || gh_status=$?
  if [[ "${gh_status}" -ne 0 ]]; then
    die "gh issue view #${issue_num} failed (issueType)"
  fi
  [[ "${result}" == "true" ]]
}

issue_metadata_ok() {
  local issue_num=$1
  issue_has_label "${issue_num}" && issue_has_type "${issue_num}"
}

repair_issue_metadata() {
  local issue_num=$1
  local edit_args=()
  if ! issue_has_label "${issue_num}"; then
    edit_args+=(--add-label "${AI_LEARNINGS_LABEL}")
  fi
  if ! issue_has_type "${issue_num}"; then
    edit_args+=(--type "${AI_LEARNINGS_ISSUE_TYPE}")
  fi
  if [[ ${#edit_args[@]} -gt 0 ]]; then
    gh issue edit "${issue_num}" "${edit_args[@]}"
  fi
}

verify_issue_metadata_or_die() {
  local issue_num=$1
  local issue_url=$2
  if issue_metadata_ok "${issue_num}"; then
    return 0
  fi
  repair_issue_metadata "${issue_num}"
  if issue_metadata_ok "${issue_num}"; then
    return 0
  fi
  die "issue #${issue_num} (${issue_url}) missing label '${AI_LEARNINGS_LABEL}' or type '${AI_LEARNINGS_ISSUE_TYPE}' after repair; do not create a duplicate -- bump or fix the existing issue"
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
    gh_status=0
    create_err="$(mktemp)"
    issue_fields=$(
      gh issue create --title "${TITLE}" --label "${AI_LEARNINGS_LABEL}" \
        --type "${AI_LEARNINGS_ISSUE_TYPE}" \
        --body-file "${BODY_FILE}" \
        --json number,url --jq '"\(.number) \(.url)"' 2>"${create_err}"
    ) || gh_status=$?
    if [[ "${gh_status}" -ne 0 ]]; then
      if [[ -s "${create_err}" ]]; then
        cat "${create_err}" >&2
      fi
      rm -f "${create_err}"
      echo "ERROR: issue create failed (need org Issue Type '${AI_LEARNINGS_ISSUE_TYPE}' and label '${AI_LEARNINGS_LABEL}')" >&2
      exit "${gh_status}"
    fi
    rm -f "${create_err}"
    read -r issue_num issue_url <<<"${issue_fields}"
    if [[ -z "${issue_num}" || -z "${issue_url}" ]]; then
      die "issue create returned unexpected output: ${issue_fields}"
    fi
    verify_issue_metadata_or_die "${issue_num}" "${issue_url}"
    printf '%s\n' "${issue_url}"
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
