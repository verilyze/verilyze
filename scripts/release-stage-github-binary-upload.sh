#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Compatibility wrapper: staging now publishes versioned platform archives.
# Prefer release-stage-github-upload.sh directly.
# Usage: release-stage-github-binary-upload.sh <release-artifacts-dir> <version> [upload-subdir]

set -euo pipefail

echo "warning: release-stage-github-binary-upload.sh is deprecated;" \
  "use release-stage-github-upload.sh" >&2

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${script_dir}/release-stage-github-upload.sh" "$@"
