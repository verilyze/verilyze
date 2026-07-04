# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Guarded recursive removal for automation scripts.
# shellcheck shell=bash

_safe_rm_rf_normalize() {
  local path="$1"
  path="${path%/}"
  printf '%s' "${path}"
}

_safe_rm_rf_reject_symlink() {
  local path="$1"
  local label="$2"
  if [[ -L "${path}" ]]; then
    echo "ERROR: refusing to remove symlink ${label}: ${path}" >&2
    return 1
  fi
}

safe_rm_rf() {
  local path="$1"
  local label="${2:-path}"
  local normalized
  local without_leading
  local home_dir="${HOME:-}"
  local repo_root="${REPO_ROOT:-}"

  if [[ -z "${path}" ]]; then
    echo "ERROR: refusing to remove empty ${label}" >&2
    return 1
  fi

  normalized="$(_safe_rm_rf_normalize "${path}")"

  if [[ "${normalized}" != /* ]]; then
    echo "ERROR: refusing to remove non-absolute ${label}: ${path}" >&2
    return 1
  fi

  case "${normalized}" in
    / | . | ..)
      echo "ERROR: refusing to remove unsafe ${label}: ${path}" >&2
      return 1
      ;;
  esac

  if [[ -n "${home_dir}" ]]; then
    home_dir="$(_safe_rm_rf_normalize "${home_dir}")"
    if [[ "${normalized}" == "${home_dir}" ]]; then
      echo "ERROR: refusing to remove home directory as ${label}" >&2
      return 1
    fi
  fi

  if [[ "${normalized}" == "/tmp" ]]; then
    echo "ERROR: refusing to remove /tmp as ${label}" >&2
    return 1
  fi

  if [[ -n "${repo_root}" ]]; then
    repo_root="$(_safe_rm_rf_normalize "${repo_root}")"
    if [[ "${normalized}" == "${repo_root}" ]]; then
      echo "ERROR: refusing to remove repository root as ${label}" >&2
      return 1
    fi
  fi

  without_leading="${normalized#/}"
  if [[ "${without_leading}" != */* ]]; then
    echo "ERROR: refusing to remove shallow ${label}: ${path}" >&2
    return 1
  fi

  _safe_rm_rf_reject_symlink "${normalized}" "${label}" || return 1

  rm -rf -- "${normalized}"
}

validate_removable_work_dir() {
  local work_dir="$1"
  local label="${2:-work dir}"
  local normalized
  local without_leading
  local repo_root="${REPO_ROOT:-}"

  if [[ -z "${work_dir}" ]]; then
    echo "ERROR: ${label} must be non-empty" >&2
    return 1
  fi

  normalized="$(_safe_rm_rf_normalize "${work_dir}")"

  if [[ "${normalized}" != /* ]]; then
    echo "ERROR: ${label} must be an absolute path: ${work_dir}" >&2
    return 1
  fi

  case "${normalized}" in
    / | . | ..)
      echo "ERROR: refusing unsafe ${label}: ${work_dir}" >&2
      return 1
      ;;
  esac

  if [[ -n "${repo_root}" ]]; then
    repo_root="$(_safe_rm_rf_normalize "${repo_root}")"
    if [[ "${normalized}" == "${repo_root}" ]]; then
      echo "ERROR: refusing repository root as ${label}" >&2
      return 1
    fi
  fi

  without_leading="${normalized#/}"
  if [[ "${without_leading}" != */* ]]; then
    echo "ERROR: ${label} path is too shallow: ${work_dir}" >&2
    return 1
  fi

  _safe_rm_rf_reject_symlink "${normalized}" "${label}" || return 1
}

validate_vendor_archive_paths() {
  local work_dir="$1"
  local output_path="$2"
  local vendor_root="${work_dir%/}/vendor-build"
  local normalized_work
  local normalized_vendor
  local parent

  if [[ -z "${output_path}" ]]; then
    echo "ERROR: vendor archive output_path must be non-empty" >&2
    return 1
  fi

  validate_removable_work_dir "${work_dir}" "work dir" || return 1

  normalized_work="$(_safe_rm_rf_normalize "${work_dir}")"
  normalized_vendor="$(_safe_rm_rf_normalize "${vendor_root}")"

  if [[ "${normalized_vendor}" != */vendor-build ]]; then
    echo "ERROR: vendor_root must end with /vendor-build" >&2
    return 1
  fi

  parent="${normalized_vendor%/vendor-build}"
  if [[ "${parent}" != "${normalized_work}" ]]; then
    echo "ERROR: vendor_root parent must equal work_dir" >&2
    return 1
  fi
}
