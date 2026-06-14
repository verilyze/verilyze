#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Native checks mirroring selected super-linter rules (no Docker).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_WORKFLOW="${ROOT_DIR}/.github/workflows/release.yml"

cd "${ROOT_DIR}"
PYTHONPATH="${ROOT_DIR}${PYTHONPATH:+:${PYTHONPATH}}" python3 - <<'PY'
from pathlib import Path

from scripts.obs_project_env import validate_obs_project_env_key_order

validate_obs_project_env_key_order(Path("packaging/obs/obs-project.env"))
PY

if [[ ! -f "${RELEASE_WORKFLOW}" ]]; then
  echo "ERROR: missing release workflow: ${RELEASE_WORKFLOW}" >&2
  exit 1
fi

if ! grep -qE 'checkov:skip=CKV_GHA_7:' "${RELEASE_WORKFLOW}"; then
  echo "ERROR: ${RELEASE_WORKFLOW} must include inline checkov:skip=CKV_GHA_7 for workflow_dispatch dry runs" >&2
  exit 1
fi
