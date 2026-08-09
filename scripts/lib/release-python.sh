# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Locate Python for portable zip archive build/extract. Sourced by release
# scripts; do not execute standalone.
#
# shellcheck shell=bash

# Print absolute path to python3 or python on stdout; exit 1 if neither exists.
vlz_release_find_python() {
  local candidate
  for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      command -v "${candidate}"
      return 0
    fi
  done
  echo "error: python3 or python is required for zip archives" >&2
  return 1
}
