# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Extract failed GNU make targets from a check log and print a rerun summary.
# Sourced by scripts/run-check.sh; test via run-check.sh --summarize-log.
#
# shellcheck shell=bash

readonly VLZ_CHECK_SUMMARY_BANNER='=== verilyze check failure summary ==='
readonly VLZ_CHECK_DIAG_HEADER='Failed command diagnostic(s):'
readonly VLZ_CHECK_DIAG_MAX_LINES=40
readonly VLZ_CHECK_DIAG_MAX_BYTES=8192
readonly VLZ_CHECK_FAILURES_SUBDIR='failures'

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

vlz_check_failure_dir() {
  local results_dir=${1:-${VLZ_CHECK_RESULTS_DIR:-}}
  [[ -n "$results_dir" ]] || return 1
  printf '%s/%s\n' "$results_dir" "$VLZ_CHECK_FAILURES_SUBDIR"
}

vlz_check_sanitize_label() {
  local label=$1
  printf '%s' "$label" | tr -c '[:alnum:]._-' '_'
}

vlz_check_record_failure() {
  local label=$1
  local exit_code=$2
  local capture_file=$3
  local failures_dir
  failures_dir="$(vlz_check_failure_dir)" || return 0
  mkdir -p "$failures_dir" || return 0
  local safe
  safe="$(vlz_check_sanitize_label "$label")"
  local base
  base="$(mktemp "${failures_dir}/${safe}.XXXXXX")" || return 0
  cp "$capture_file" "${base}.log"
  {
    printf 'label=%s\n' "$label"
    printf 'exit_code=%s\n' "$exit_code"
  } >"${base}.meta"
  rm -f "$base"
}

vlz_check_read_meta() {
  # Parse .meta without sourcing (labels may contain shell metacharacters).
  # Sets caller variables named by $2 (label) and $3 (exit_code) via printf -v.
  local meta_file=$1
  local label_var=$2
  local exit_var=$3
  local key
  local value
  local parsed_label=""
  local parsed_exit=""
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    case "$key" in
      label) parsed_label=$value ;;
      exit_code) parsed_exit=$value ;;
    esac
  done <"$meta_file"
  printf -v "$label_var" '%s' "$parsed_label"
  printf -v "$exit_var" '%s' "$parsed_exit"
}

vlz_check_append_diagnostic_excerpt() {
  local lines_ref=$1
  local label=$2
  local exit_code=$3
  local log_file=$4
  local -n out_lines=$lines_ref
  local bytes=0
  local line_count=0
  local line

  out_lines+=("  - ${label} (exit ${exit_code}):")
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_count++)) || true
    if ((line_count > VLZ_CHECK_DIAG_MAX_LINES)); then
      out_lines+=("    ... (truncated; see full log above)")
      break
    fi
    local add=${#line}
    if ((bytes + add > VLZ_CHECK_DIAG_MAX_BYTES)); then
      out_lines+=("    ... (truncated; see full log above)")
      break
    fi
    bytes=$((bytes + add))
    out_lines+=("    ${line}")
  done <"$log_file"
}

vlz_check_append_command_diagnostics() {
  local lines_ref=$1
  local results_dir=$2
  local failures_dir
  local meta
  local label
  local exit_code
  local log_path
  local -a metas=()

  failures_dir="$(vlz_check_failure_dir "$results_dir")" || return 0
  [[ -d "$failures_dir" ]] || return 0

  while IFS= read -r meta; do
    metas+=("$meta")
  done < <(find "$failures_dir" -maxdepth 1 -name '*.meta' -print | sort)

  ((${#metas[@]} > 0)) || return 0

  local -n _lines=$lines_ref
  _lines+=("$VLZ_CHECK_DIAG_HEADER")
  for meta in "${metas[@]}"; do
    label=""
    exit_code=""
    vlz_check_read_meta "$meta" label exit_code
    [[ -n "$label" && -n "$exit_code" ]] || continue
    log_path="${meta%.meta}.log"
    [[ -f "$log_path" ]] || continue
    vlz_check_append_diagnostic_excerpt "$lines_ref" "$label" "$exit_code" "$log_path"
  done
  _lines+=("Full command output is replayed earlier in this log.")
}

vlz_check_print_failure_summary() {
  local log_file=$1
  local results_dir=${2:-${VLZ_CHECK_RESULTS_DIR:-}}
  local targets=()
  local target
  local lines=()
  local summary_file=${GITHUB_STEP_SUMMARY:-}

  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    targets+=("$target")
  done < <(vlz_check_summary_failed_targets "$log_file")

  if ((${#targets[@]} == 0)); then
    local failures_probe
    failures_probe="$(vlz_check_failure_dir "$results_dir" 2>/dev/null || true)"
    if [[ -z "$failures_probe" || ! -d "$failures_probe" ]] || \
      [[ -z "$(find "$failures_probe" -maxdepth 1 -name '*.meta' -print -quit 2>/dev/null)" ]]; then
      return 0
    fi
  fi

  lines+=("$VLZ_CHECK_SUMMARY_BANNER")
  if ((${#targets[@]} > 0)); then
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
  fi

  if [[ -n "$results_dir" ]]; then
    vlz_check_append_command_diagnostics lines "$results_dir"
  fi

  local line
  for line in "${lines[@]}"; do
    echo "$line" >&2
    if [[ -n "$summary_file" ]]; then
      echo "$line" >>"$summary_file"
    fi
  done
}
