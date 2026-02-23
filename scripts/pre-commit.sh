#!/bin/sh
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Pre-commit hook wrapper: runs headers, diagram scripts, and Rust formatting.
# Installed by scripts/install-hooks.sh.

set -e
cd "$(git rev-parse --show-toplevel)"
./scripts/pre-commit-headers.sh
./scripts/pre-commit-diagrams.sh
# Auto-format Rust code; fail if formatting changed files (user must add and recommit)
cargo fmt
if git diff --name-only | grep -q '\.rs$'; then
    echo "Rust files were reformatted by cargo fmt. Please review and git add them, then commit again." >&2
    exit 1
fi
