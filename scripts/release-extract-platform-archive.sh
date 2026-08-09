#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Extract a platform release archive and assert the expected member layout.
# Prints the absolute path to the executable on stdout.
# Usage:
#   release-extract-platform-archive.sh \
#     --archive <path> \
#     --platform <linux-x86_64|macos-aarch64|windows-x86_64> \
#     --version <X.Y.Z> \
#     --dest <dir>

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-artifact-names.sh
source "${script_dir}/lib/release-artifact-names.sh"
# shellcheck source=lib/ci-input-validate.sh
source "${script_dir}/lib/ci-input-validate.sh"
# shellcheck source=lib/release-python.sh
source "${script_dir}/lib/release-python.sh"

usage() {
  cat >&2 <<'EOF'
usage: release-extract-platform-archive.sh \
  --archive <path> \
  --platform <linux-x86_64|macos-aarch64|windows-x86_64> \
  --version <X.Y.Z> \
  --dest <dir>
EOF
  exit 2
}

archive=""
platform=""
version=""
dest=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive)
      archive="${2:-}"
      shift 2
      ;;
    --platform)
      platform="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --dest)
      dest="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "${archive}" || -z "${platform}" || -z "${version}" || -z "${dest}" ]]; then
  usage
fi
if [[ ! -f "${archive}" ]]; then
  echo "error: archive does not exist: ${archive}" >&2
  exit 1
fi

if ! vlz_require_release_semver "${version}"; then
  exit 2
fi

mkdir -p "${dest}"
dest="$(cd "${dest}" && pwd)"
wrapper="$(release_wrapper_dirname "${version}" "${platform}")"
exec_rel="$(release_exec_relpath "${platform}")"

rm -rf "${dest:?}/${wrapper}"
case "${archive}" in
  *.tar.gz)
    if tar -tzf "${archive}" | grep -qE '(^/)|(^\\.\\./)|(/\.\./)|(\\)'; then
      echo "error: archive contains unsafe member paths" >&2
      exit 1
    fi
    tar -xzf "${archive}" -C "${dest}"
    ;;
  *.zip)
    python="$(vlz_release_find_python)"
    "${python}" - "${archive}" "${dest}" <<'PY'
import os
import sys
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
dest = Path(sys.argv[2]).resolve()
dest.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive) as zf:
    for name in zf.namelist():
        if not name or name.startswith("/") or "\\" in name:
            raise SystemExit(f"error: archive contains unsafe member path: {name}")
        parts = Path(name).parts
        if ".." in parts:
            raise SystemExit(f"error: archive contains unsafe member path: {name}")
        target = (dest / name).resolve()
        dest_prefix = str(dest)
        target_str = str(target)
        if target != dest and not (
            target_str == dest_prefix or target_str.startswith(dest_prefix + os.sep)
        ):
            raise SystemExit(f"error: archive member escapes dest: {name}")
    zf.extractall(dest)
PY
    ;;
  *)
    echo "error: unsupported archive type: ${archive}" >&2
    exit 1
    ;;
esac

wrapper_root="${dest}/${wrapper}"
if [[ ! -d "${wrapper_root}" ]]; then
  echo "error: missing wrapper directory after extract: ${wrapper}" >&2
  exit 1
fi

required=(
  "${wrapper_root}/LICENSE"
  "${wrapper_root}/THIRD-PARTY-LICENSES"
  "${wrapper_root}/INSTALL.md"
  "${wrapper_root}/${exec_rel}"
)

if release_is_windows_platform "${platform}"; then
  required+=("${wrapper_root}/verilyze.conf.example")
else
  required+=(
    "${wrapper_root}/share/doc/verilyze/verilyze.conf.example"
    "${wrapper_root}/share/man/man1/vlz.1"
    "${wrapper_root}/share/man/man5/verilyze.conf.5"
    "${wrapper_root}/share/bash-completion/completions/vlz"
    "${wrapper_root}/share/zsh/site-functions/_vlz"
    "${wrapper_root}/share/fish/vendor_completions.d/vlz.fish"
  )
fi

for path in "${required[@]}"; do
  if [[ ! -f "${path}" ]]; then
    echo "error: missing archive member: ${path#"${dest}"/}" >&2
    exit 1
  fi
done

exec_path="${wrapper_root}/${exec_rel}"
if ! release_is_windows_platform "${platform}"; then
  if [[ ! -x "${exec_path}" ]]; then
    echo "error: executable bit not set on ${exec_rel}" >&2
    exit 1
  fi
fi

realpath "${exec_path}"
