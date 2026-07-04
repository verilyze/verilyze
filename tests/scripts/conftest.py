# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Pytest configuration for scripts tests."""

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest


def _load_sibling_module(module_name: str):
    path = Path(__file__).resolve().parent / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(
        f"tests.scripts.{module_name}",
        path,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load test helper module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_repo_root = _load_sibling_module("repo_root").repo_root()
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from tests.scripts.workspace_helpers import (  # noqa: E402
    obs_dry_run_work_dir as create_obs_dry_run_work_dir,
    safe_rmtree_obs_work,
)


@pytest.fixture
def obs_dry_run_work_dir(request: pytest.FixtureRequest) -> Iterator[Path]:
    """Per-test OBS staging dir under target/pytest-obs-work/ with cleanup."""
    work = create_obs_dry_run_work_dir(request.node.name)
    try:
        yield work
    finally:
        safe_rmtree_obs_work(work)
