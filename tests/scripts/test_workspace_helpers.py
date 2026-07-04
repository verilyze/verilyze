# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for tests.scripts.workspace_helpers."""

from tests.scripts.workspace_helpers import (
    obs_dry_run_work_dir,
    repo_root,
    safe_rmtree_obs_work,
)


def test_obs_dry_run_work_dir_uses_target_not_tmp() -> None:
    work = obs_dry_run_work_dir("unit-test-work-dir")
    try:
        assert work.is_dir()
        assert work.parent.name == "master"
        assert work.parent.parent.name == "pytest-obs-work"
        assert work.parent.parent.parent.name == "target"
        assert work.parent.parent.parent.parent == repo_root()
    finally:
        safe_rmtree_obs_work(work)
