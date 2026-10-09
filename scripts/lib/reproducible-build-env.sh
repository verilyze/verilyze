#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# NFR-006 helpers: pin timestamps and remap paths for reproducible cargo
# release builds. Source from release CI and check-reproducible-build.sh.
#
# Usage (from a sourced context):
#   source scripts/lib/reproducible-build-env.sh
#   vlz_apply_reproducible_build_env /path/to/repo

# shellcheck shell=bash

vlz_apply_reproducible_build_env() {
  local root="${1:-}"
  if [[ -z "${root}" ]]; then
    echo "error: vlz_apply_reproducible_build_env requires a repo root" >&2
    return 2
  fi
  if [[ ! -d "${root}" ]]; then
    echo "error: repo root does not exist: ${root}" >&2
    return 2
  fi
  root="$(cd "${root}" && pwd)"

  if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    if git -C "${root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      SOURCE_DATE_EPOCH="$(git -C "${root}" log -1 --pretty=%ct)"
    else
      SOURCE_DATE_EPOCH=0
    fi
  fi
  export SOURCE_DATE_EPOCH
  export CARGO_INCREMENTAL=0
  export PYTHONHASHSEED=0

  local remap="--remap-path-prefix=${root}=/build"
  if [[ -n "${RUSTFLAGS:-}" ]]; then
    case " ${RUSTFLAGS} " in
      *" ${remap} "*) ;;
      *)
        export RUSTFLAGS="${RUSTFLAGS} ${remap}"
        ;;
    esac
  else
    export RUSTFLAGS="${remap}"
  fi
}
