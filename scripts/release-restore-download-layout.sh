#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# After gh release download, assets use basenames only. Reconstruct the layout
# expected by release-list-artifacts.sh and SHA256SUMS path entries.
# Usage: release-restore-download-layout.sh <dir>

set -euo pipefail

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

(
  cd "${dir}"
  mkdir -p vlz-linux-x86_64 deb-package rpm-package/x86_64

  if [[ -f vlz ]]; then
    mv -f vlz vlz-linux-x86_64/
    if [[ -f vlz.sigstore.json ]]; then
      mv -f vlz.sigstore.json vlz-linux-x86_64/
    fi
    if [[ -f vlz.intoto.jsonl ]]; then
      mv -f vlz.intoto.jsonl vlz-linux-x86_64/
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
