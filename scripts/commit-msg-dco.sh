#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Commit-msg hook: verify commit message contains Signed-off-by (DCO).
# Installed by scripts/install-hooks.sh.
#
# Use 'git commit -s' to add signoff automatically.

set -e

COMMIT_MSG_FILE="$1"
if [ ! -f "$COMMIT_MSG_FILE" ]; then
    echo "Error: No commit message file." >&2
    exit 1
fi

if ! grep -q '^Signed-off-by:' "$COMMIT_MSG_FILE"; then
    echo "Error: Commit message must include a Signed-off-by line (DCO)." >&2
    echo "Use 'git commit -s' to add it automatically." >&2
    echo "See https://developercertificate.org/" >&2
    exit 1
fi
