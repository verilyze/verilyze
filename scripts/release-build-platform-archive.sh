#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Build a versioned platform release archive once (do not rebuild at publish).
# Usage:
#   release-build-platform-archive.sh \
#     --platform <linux-x86_64|macos-aarch64|windows-x86_64> \
#     --version <X.Y.Z> \
#     --binary <path-to-vlz-or-vlz.exe> \
#     --repo-root <path> \
#     --output-dir <dir>

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
usage: release-build-platform-archive.sh \
  --platform <linux-x86_64|macos-aarch64|windows-x86_64> \
  --version <X.Y.Z> \
  --binary <path> \
  --repo-root <path> \
  --output-dir <dir>
EOF
  exit 2
}

platform=""
version=""
binary=""
repo_root=""
output_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      platform="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --repo-root)
      repo_root="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
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

if [[ -z "${platform}" || -z "${version}" || -z "${binary}" || -z "${repo_root}" || -z "${output_dir}" ]]; then
  usage
fi

known=0
for p in "${RELEASE_PLATFORMS[@]}"; do
  if [[ "${p}" == "${platform}" ]]; then
    known=1
    break
  fi
done
if [[ "${known}" -ne 1 ]]; then
  echo "error: unknown platform: ${platform}" >&2
  exit 1
fi

if ! vlz_require_release_semver "${version}"; then
  exit 2
fi

if [[ ! -f "${binary}" ]]; then
  echo "error: binary does not exist: ${binary}" >&2
  exit 1
fi
if [[ ! -d "${repo_root}" ]]; then
  echo "error: repo root does not exist: ${repo_root}" >&2
  exit 1
fi

repo_root="$(cd "${repo_root}" && pwd)"
mkdir -p "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"

wrapper="$(release_wrapper_dirname "${version}" "${platform}")"
archive_name="$(release_archive_basename "${version}" "${platform}")"
stage="$(mktemp -d)"
trap 'rm -rf "${stage}"' EXIT

wrapper_root="${stage}/${wrapper}"
mkdir -p "${wrapper_root}"

install_file() {
  local src="$1"
  local dest="$2"
  local mode="${3:-644}"
  if [[ ! -f "${src}" ]]; then
    echo "error: missing archive member source: ${src}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${dest}")"
  install -m "${mode}" "${src}" "${dest}"
}

# Wrapper-root docs (not installed under PREFIX by make install).
install_file "${repo_root}/LICENSE" "${wrapper_root}/LICENSE"
install_file "${repo_root}/THIRD-PARTY-LICENSES" "${wrapper_root}/THIRD-PARTY-LICENSES"
install_file "${repo_root}/docs/install-archive.md" "${wrapper_root}/INSTALL.md"

if release_is_windows_platform "${platform}"; then
  install_file "${binary}" "${wrapper_root}/vlz.exe" 755
  install_file \
    "${repo_root}/verilyze.conf.example" \
    "${wrapper_root}/verilyze.conf.example"
else
  install_file "${binary}" "${wrapper_root}/bin/vlz" 755
  install_file \
    "${repo_root}/verilyze.conf.example" \
    "${wrapper_root}/share/doc/verilyze/verilyze.conf.example"
  install_file \
    "${repo_root}/man/vlz.1" \
    "${wrapper_root}/share/man/man1/vlz.1"
  install_file \
    "${repo_root}/man/verilyze.conf.5" \
    "${wrapper_root}/share/man/man5/verilyze.conf.5"
  install_file \
    "${repo_root}/completions/vlz.bash" \
    "${wrapper_root}/share/bash-completion/completions/vlz"
  install_file \
    "${repo_root}/completions/_vlz" \
    "${wrapper_root}/share/zsh/site-functions/_vlz"
  install_file \
    "${repo_root}/completions/vlz.fish" \
    "${wrapper_root}/share/fish/vendor_completions.d/vlz.fish"
fi

archive_path="${output_dir}/${archive_name}"
rm -f "${archive_path}"

pin_tree_mtime() {
  local root="$1"
  find "${root}" -exec touch -t 197001010000 {} +
}

create_tar_gz() {
  local out="$1"
  # Prefer GNU tar deterministic flags; fall back to bsdtar (macOS).
  if tar --version 2>&1 | grep -q 'GNU tar'; then
    tar \
      --sort=name \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      --mtime='UTC 1970-01-01' \
      -C "${stage}" \
      -cf - \
      "${wrapper}" \
      | gzip -n > "${out}"
  else
    # bsdtar: COPYFILE_DISABLE avoids macOS xattrs. Pin mtime for stability.
    pin_tree_mtime "${wrapper_root}"
    local -a tar_args=(-C "${stage}" -cf - "${wrapper}")
    if COPYFILE_DISABLE=1 tar --help 2>&1 | grep -q -- '--uid'; then
      tar_args=(--uid 0 --gid 0 "${tar_args[@]}")
    fi
    COPYFILE_DISABLE=1 tar "${tar_args[@]}" | gzip -n > "${out}"
  fi
}
create_zip() {
  local out="$1"
  local python
  python="$(vlz_release_find_python)"
  "${python}" - "${stage}" "${wrapper}" "${out}" <<'PY'
import sys
import zipfile
from pathlib import Path

stage = Path(sys.argv[1])
wrapper = sys.argv[2]
out = Path(sys.argv[3])
root = stage / wrapper
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            zf.write(path, path.relative_to(stage).as_posix())
PY
}

if release_is_windows_platform "${platform}"; then
  create_zip "${archive_path}"
else
  create_tar_gz "${archive_path}"
fi

if [[ ! -f "${archive_path}" ]]; then
  echo "error: failed to create archive: ${archive_path}" >&2
  exit 1
fi

printf '%s\n' "${archive_path}"
