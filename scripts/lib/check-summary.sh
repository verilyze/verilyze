# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Extract failed GNU make targets from a check log and print a rerun summary.
# Sourced by scripts/run-check.sh; test via run-check.sh --summarize-log.
#
# shellcheck shell=bash

readonly VLZ_CHECK_SUMMARY_BANNER='=== verilyze check failure summary ==='

# Regex for make failure lines: make[1]: *** [clippy] Error 1
readonly VLZ_CHECK_MAKE_FAIL_REGEX='make(\[[0-9]+\])?: \*\*\* \[[^]]+\]'

# Aggregate targets that duplicate leaf failures; omit from rerun hints.
readonly VLZ_CHECK_AGGREGATE_TARGETS=' check check-parallel check-fast check-fast-parallel fuzz-then-coverage setup '

vlz_check_summary_failed_targets() {
  local log_file=$1
  grep -oE "$VLZ_CHECK_MAKE_FAIL_REGEX" "$log_file" \
    | sed -E 's/.*\[(Makefile:[0-9]+: )?([^]]+)\].*/\2/' \
    | sort -u
}

vlz_check_summary_rerun_targets() {
  local log_file=$1
  local target
  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    case "$VLZ_CHECK_AGGREGATE_TARGETS" in
      *" ${target} "*) continue ;;
    esac
    printf '%s\n' "$target"
  done < <(vlz_check_summary_failed_targets "$log_file")
}

vlz_check_print_failure_summary() {
  local log_file=$1
  local targets=()
  local target
  local lines=()
  local summary_file=${GITHUB_STEP_SUMMARY:-}

  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    targets+=("$target")
  done < <(vlz_check_summary_failed_targets "$log_file")

  if ((${#targets[@]} == 0)); then
    return 0
  fi

  lines+=("$VLZ_CHECK_SUMMARY_BANNER")
  lines+=("Failed make target(s) (${#targets[@]}):")
  for target in "${targets[@]}"; do
    lines+=("  - ${target}")
  done

  local rerun=()
  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    rerun+=("make ${target}")
  done < <(vlz_check_summary_rerun_targets "$log_file")

  if ((${#rerun[@]} > 0)); then
    lines+=("Re-run locally:")
    for cmd in "${rerun[@]}"; do
      lines+=("  ${cmd}")
    done
  fi

  local line
  for line in "${lines[@]}"; do
    echo "$line" >&2
    if [[ -n "$summary_file" ]]; then
      echo "$line" >>"$summary_file"
    fi
  done
}
