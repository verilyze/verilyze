# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared release platform archive naming and layout constants.
# Source from other release scripts; do not execute directly.
#
# shellcheck shell=bash

# Short platform tokens used in archive basenames (room for -musl later).
# Consumed by staging, round-trip, merge, and extract scripts that source this
# library; keep the array even when ShellCheck analyzes this file alone.
# shellcheck disable=SC2034
readonly RELEASE_PLATFORMS=(
  linux-x86_64
  macos-aarch64
  windows-x86_64
)

# Actions artifact container names (unique; not the published GitHub asset).
readonly RELEASE_ACTIONS_ARTIFACT_PREFIX="vlz"

release_is_windows_platform() {
  local platform="${1:?platform required}"
  [[ "${platform}" == windows-* ]]
}

release_archive_extension() {
  local platform="${1:?platform required}"
  if release_is_windows_platform "${platform}"; then
    printf 'zip\n'
  else
    printf 'tar.gz\n'
  fi
}

# Published GitHub Release basename (unique across platforms).
release_archive_basename() {
  local version="${1:?version required}"
  local platform="${2:?platform required}"
  # Trim newline from nested helper before composing the basename.
  local ext
  ext="$(release_archive_extension "${platform}")"
  printf 'vlz-%s-%s.%s\n' "${version}" "${platform}" "${ext}"
}

# Top-level wrapper directory inside the archive (matches archive stem).
release_wrapper_dirname() {
  local version="${1:?version required}"
  local platform="${2:?platform required}"
  printf 'vlz-%s-%s\n' "${version}" "${platform}"
}

# Path of the executable relative to the wrapper directory.
release_exec_relpath() {
  local platform="${1:?platform required}"
  if release_is_windows_platform "${platform}"; then
    printf 'vlz.exe\n'
  else
    printf 'bin/vlz\n'
  fi
}

# Cargo / local build output basename for a platform.
release_cargo_binary_basename() {
  local platform="${1:?platform required}"
  if release_is_windows_platform "${platform}"; then
    printf 'vlz.exe\n'
  else
    printf 'vlz\n'
  fi
}

# Actions upload-artifact name for a platform matrix cell.
release_actions_artifact_name() {
  local platform="${1:?platform required}"
  printf '%s-%s\n' "${RELEASE_ACTIONS_ARTIFACT_PREFIX}" "${platform}"
}

# SLSA provenance artifact basename produced by the generic generator job.
release_slsa_provenance_basename() {
  local platform="${1:?platform required}"
  local actions_name
  actions_name="$(release_actions_artifact_name "${platform}")"
  printf 'slsa-%s.intoto.jsonl\n' "${actions_name}"
}

# Map GitHub Actions runner.os / matrix shorthand to platform token.
release_platform_from_matrix_os() {
  local os="${1:?os required}"
  case "${os}" in
    ubuntu-latest | Linux | linux) printf 'linux-x86_64\n' ;;
    macos-latest | macOS | macos) printf 'macos-aarch64\n' ;;
    windows-latest | Windows | windows) printf 'windows-x86_64\n' ;;
    *)
      echo "error: unknown release matrix OS: ${os}" >&2
      return 1
      ;;
  esac
}

# Published platform archive basename (flat GitHub Release asset name).
release_is_slsa_archive_basename() {
  local basename="${1:?basename required}"
  case "${basename}" in
    vlz-*-linux-x86_64.tar.gz \
    | vlz-*-macos-aarch64.tar.gz \
    | vlz-*-windows-x86_64.zip)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
