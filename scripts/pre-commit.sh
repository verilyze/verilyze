#!/bin/sh
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Pre-commit hook wrapper: runs headers and diagram scripts.
# Installed by scripts/install-hooks.sh.

set -e
cd "$(git rev-parse --show-toplevel)"
./scripts/pre-commit-headers.sh
./scripts/pre-commit-diagrams.sh
