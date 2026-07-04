# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for safe OBS pytest work directory removal."""

from pathlib import Path

import pytest

from tests.scripts.repo_root import repo_root
from tests.scripts.workspace_helpers import (
    obs_dry_run_work_dir,
    pytest_obs_work_root,
    safe_rmtree_obs_work,
    safe_rmtree_pytest_obs_work_root,
)


def test_safe_rmtree_obs_work_allows_per_test_subdirectory() -> None:
    work = obs_dry_run_work_dir("safe-rmtree-allows-subdir")
    marker = work / "marker.txt"
    marker.write_text("x", encoding="utf-8")
    safe_rmtree_obs_work(work)
    assert not work.exists()


def test_safe_rmtree_obs_work_rejects_repo_root() -> None:
    with pytest.raises(ValueError, match="outside"):
        safe_rmtree_obs_work(repo_root())


def test_safe_rmtree_obs_work_rejects_target_directory() -> None:
    with pytest.raises(ValueError, match="outside"):
        safe_rmtree_obs_work(repo_root() / "target")


def test_safe_rmtree_obs_work_rejects_pytest_obs_work_root() -> None:
    with pytest.raises(ValueError, match="subdirectory"):
        safe_rmtree_obs_work(pytest_obs_work_root())


def test_safe_rmtree_obs_work_rejects_paths_outside_prefix(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="outside"):
        safe_rmtree_obs_work(outside)


def test_safe_rmtree_obs_work_rejects_symlink(tmp_path: Path) -> None:
    root = pytest_obs_work_root()
    worker_dir = root / "master"
    worker_dir.mkdir(parents=True, exist_ok=True)
    real = worker_dir / "real-case"
    real.mkdir()
    link = worker_dir / "linked-case"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        safe_rmtree_obs_work(link)
    assert real.is_dir()


def test_obs_dry_run_work_dir_includes_worker_segment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw2")
    work = obs_dry_run_work_dir("worker-segment-test")
    try:
        assert work.parent.name == "gw2"
        assert work.parent.parent.name == "pytest-obs-work"
    finally:
        safe_rmtree_obs_work(work)


def test_safe_rmtree_pytest_obs_work_root_removes_only_exact_root() -> None:
    root = pytest_obs_work_root()
    child = root / "cleanup-root-child"
    child.mkdir(parents=True)
    safe_rmtree_pytest_obs_work_root()
    assert not root.exists()


def test_safe_rmtree_pytest_obs_work_root_rejects_other_paths() -> None:
    with pytest.raises(ValueError, match="exact"):
        safe_rmtree_pytest_obs_work_root(repo_root() / "target")
