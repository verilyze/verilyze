#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# After gh release download, assets use basenames only. Reconstruct the layout
# expected by release-list-artifacts.sh and SHA256SUMS path entries.
# Usage: release-restore-download-layout.sh <dir>

set -euo pipefail

readonly LINUX_ASSET_NAME='vlz-linux-x86_64'
readonly MACOS_ASSET_NAME='vlz-macos-aarch64'
readonly WINDOWS_ASSET_NAME='vlz-windows-x86_64.exe'

usage() {
  echo "usage: $0 <download-dir>" >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

dir="$1"
if [[ ! -d "${dir}" ]]; then
  echo "error: directory does not exist: ${dir}" >&2
  exit 1
fi

restore_named_binary() {
  local asset_name="$1"
  local target_dir="$2"
  local target_file="$3"
  local staging="${asset_name}.restore-staging"

  if [[ ! -f "${asset_name}" ]]; then
    return 0
  fi
  mv -f "${asset_name}" "${staging}"
  mkdir -p "${target_dir}"
  mv -f "${staging}" "${target_dir}/${target_file}"
  if [[ -f "${asset_name}.sigstore.json" ]]; then
    mv -f "${asset_name}.sigstore.json" "${target_dir}/${target_file}.sigstore.json"
  fi
  if [[ -f "${asset_name}.intoto.jsonl" ]]; then
    mv -f "${asset_name}.intoto.jsonl" "${target_dir}/${target_file}.intoto.jsonl"
  fi
}

(
  cd "${dir}"
  mkdir -p deb-package rpm-package/x86_64

  restore_named_binary "${LINUX_ASSET_NAME}" vlz-linux-x86_64 vlz
  restore_named_binary "${MACOS_ASSET_NAME}" vlz-macos-aarch64 vlz
  restore_named_binary "${WINDOWS_ASSET_NAME}" vlz-windows-x86_64 vlz.exe

  if [[ -f vlz ]]; then
    mkdir -p vlz-linux-x86_64
    mv -f vlz vlz-linux-x86_64/
    if [[ -f vlz.sigstore.json ]]; then
      mv -f vlz.sigstore.json vlz-linux-x86_64/
    fi
    if [[ -f vlz.intoto.jsonl ]]; then
      mv -f vlz.intoto.jsonl vlz-linux-x86_64/
    fi
  fi

  if [[ -f vlz.exe ]]; then
    mkdir -p vlz-windows-x86_64
    mv -f vlz.exe vlz-windows-x86_64/
    if [[ -f vlz.exe.sigstore.json ]]; then
      mv -f vlz.exe.sigstore.json vlz-windows-x86_64/
    fi
    if [[ -f vlz.exe.intoto.jsonl ]]; then
      mv -f vlz.exe.intoto.jsonl vlz-windows-x86_64/
    fi
  fi

  shopt -s nullglob
  for deb in *.deb; do
    [[ -f "${deb}" ]] || continue
    mv -f "${deb}" deb-package/
    if [[ -f "${deb}.sigstore.json" ]]; then
      mv -f "${deb}.sigstore.json" deb-package/
    fi
    if [[ -f "${deb}.intoto.jsonl" ]]; then
      mv -f "${deb}.intoto.jsonl" deb-package/
    fi
  done

  for rpm in *.rpm; do
    [[ -f "${rpm}" ]] || continue
    mv -f "${rpm}" rpm-package/x86_64/
    if [[ -f "${rpm}.sigstore.json" ]]; then
      mv -f "${rpm}.sigstore.json" rpm-package/x86_64/
    fi
    if [[ -f "${rpm}.intoto.jsonl" ]]; then
      mv -f "${rpm}.intoto.jsonl" rpm-package/x86_64/
    fi
  done
)
