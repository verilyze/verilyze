#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Re-apply vlz scan exit code after artifact/SARIF upload (FR-010).
#
# Usage: SCAN_EXIT=<code> ci-enforce-scan-exit.sh

set -euo pipefail

: "${SCAN_EXIT:?SCAN_EXIT is required}"

case "${SCAN_EXIT}" in
  *[!0-9]*)
    echo "::error::invalid scan exit code: ${SCAN_EXIT}" >&2
    exit 1
    ;;
esac

if (( SCAN_EXIT > 255 )); then
  echo "::error::scan exit code out of range: ${SCAN_EXIT}" >&2
  exit 1
fi

exit "${SCAN_EXIT}"
