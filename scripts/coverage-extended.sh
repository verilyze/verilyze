#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Extended coverage for nightly / README badges: default gates plus
# perf-instrumentation, python-tier-d, and minimal-feature matrix tests.
#
# Run from the repository root: ./scripts/coverage-extended.sh
# Or: make coverage-extended

set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

export VLZ_COVERAGE_EXTENDED=1
exec ./scripts/coverage.sh
