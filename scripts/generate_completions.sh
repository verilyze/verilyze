#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Generate shell completions (bash, zsh, fish) from the vlz binary.
# Usage: scripts/generate_completions.sh <path-to-vlz-binary>
#
# Run from repository root. Creates completions/ in the current directory.

set -e

BIN="${1:?Usage: $0 <path-to-vlz-binary>}"
mkdir -p completions
"$BIN" generate-completions bash > completions/vlz.bash
"$BIN" generate-completions zsh > completions/_vlz
"$BIN" generate-completions fish > completions/vlz.fish
