#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Pre-commit hook logic: when architecture/*.mmd is staged, run
# make update-doc-diagrams and stage the updated README.md and CONTRIBUTING.md.
#
# Invoked by .git/hooks/pre-commit when installed via scripts/install-hooks.sh.
#
# Run from repository root: ./scripts/pre-commit-diagrams.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

staged_mmd=$(git diff --cached --name-only 2>/dev/null | grep -E "^architecture/.*\.mmd$" || true)
if [ -z "$staged_mmd" ]; then
  exit 0
fi

make update-doc-diagrams
git add README.md CONTRIBUTING.md
echo "pre-commit-diagrams: updated embedded diagrams for staged .mmd changes."
