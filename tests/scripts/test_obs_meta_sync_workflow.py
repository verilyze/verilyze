# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS _meta sync workflow on main."""

from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_WORKFLOW = _ROOT / ".github" / "workflows" / "obs-meta-sync.yml"


def test_obs_meta_sync_workflow_runs_on_main_meta_changes() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "branches: [main]" in text
    assert "packaging/obs/**/_meta" in text


def test_obs_meta_sync_workflow_pushes_project_and_package_meta() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "./scripts/sync-obs-project-meta.sh" in text
    assert "--check" in text
    assert "--push" in text
    assert "secrets.OBS_USER" in text
    assert "secrets.OBS_PASSWORD" in text
