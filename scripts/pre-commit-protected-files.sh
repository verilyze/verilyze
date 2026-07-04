#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Pre-commit hook logic: reject staged changes to protected files.
# Invoked by scripts/pre-commit.sh when installed via scripts/install-hooks.sh.
#
# Run from repository root: ./scripts/pre-commit-protected-files.sh

set -euo pipefail

readonly PROTECTED_FILES=(LICENSE)

staged="$(git diff --cached --name-only)"
if [[ -z "${staged}" ]]; then
  exit 0
fi

for protected in "${PROTECTED_FILES[@]}"; do
  if printf '%s\n' "${staged}" | grep -qx "${protected}"; then
    echo "ERROR: ${protected} is protected and must not be modified." >&2
    echo "See CONTRIBUTING.md (Copyright and licensing)." >&2
    exit 1
  fi
done
