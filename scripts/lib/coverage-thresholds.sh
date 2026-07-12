# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared coverage fail-under thresholds (NFR-012, NFR-017).
# Sourced by scripts/coverage.sh; do not execute directly.
#
# shellcheck shell=bash

# shellcheck disable=SC2034
# Workspace aggregate Rust gates (unchanged project policy).
VLZ_RUST_FAIL_UNDER_LINES=85
VLZ_RUST_FAIL_UNDER_FUNCTIONS=80
VLZ_RUST_FAIL_UNDER_REGIONS=85

# Python aggregate and per-module line gate.
VLZ_PYTHON_FAIL_UNDER_LINES=95

# Ship-pr stricter tier for newly added Rust files (not used in make check).
VLZ_NEW_RUST_MIN_LINE_RATE=95
VLZ_NEW_RUST_MIN_FUNCTION_RATE=90
VLZ_NEW_RUST_MIN_REGION_RATE=95
