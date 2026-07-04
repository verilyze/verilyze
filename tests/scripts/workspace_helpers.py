# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared version and OBS constants for script tests (DRY with Cargo.toml)."""

import re
import shutil
import tomllib
import os
from pathlib import Path

from tests.scripts.repo_root import repo_root

_REPO_ROOT = repo_root()
_OBS_ENV = _REPO_ROOT / "packaging" / "obs" / "obs-project.env"
_PYTEST_OBS_WORK_ROOT = _REPO_ROOT / "target" / "pytest-obs-work"
_CHANGES_HEADER_VERSION_RE = re.compile(r" - (\d+\.\d+\.\d+)\s*$")
_PYTEST_XDIST_WORKER_ENV = "PYTEST_XDIST_WORKER"


def _pytest_worker_segment() -> str:
    """Isolate OBS work dirs per pytest-xdist worker when parallelized."""
    worker = os.environ.get(_PYTEST_XDIST_WORKER_ENV, "")
    if not worker or worker == "master":
        return "master"
    safe_worker = re.sub(r"[^\w.-]+", "_", worker).strip("_")
    return safe_worker or "worker"


def pytest_obs_work_root() -> Path:
    return _PYTEST_OBS_WORK_ROOT


def _resolved_under_pytest_obs_work(path: Path) -> Path:
    resolved = path.resolve()
    root = _PYTEST_OBS_WORK_ROOT.resolve()
    if resolved == root:
        raise ValueError(
            f"path must be a subdirectory of {root}, not the root itself: {path}"
        )
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path is outside {root}: {path}") from exc
    return resolved


def safe_rmtree_obs_work(path: Path) -> None:
    """Remove a per-test OBS work directory under ``target/pytest-obs-work/``."""
    if not str(path).strip():
        raise ValueError("path must be non-empty")
    if path.is_symlink():
        raise ValueError(f"path must not be a symlink: {path}")
    resolved = _resolved_under_pytest_obs_work(path)
    forbidden = {
        _REPO_ROOT.resolve(),
        (_REPO_ROOT / "target").resolve(),
        _PYTEST_OBS_WORK_ROOT.resolve(),
    }
    if resolved in forbidden:
        raise ValueError(f"refusing to remove forbidden path: {path}")
    if resolved.exists():
        shutil.rmtree(resolved)


def safe_rmtree_pytest_obs_work_root(path: Path | None = None) -> None:
    """Remove the entire ``target/pytest-obs-work/`` tree."""
    root = _PYTEST_OBS_WORK_ROOT.resolve()
    target = (path or _PYTEST_OBS_WORK_ROOT).resolve()
    if (path or _PYTEST_OBS_WORK_ROOT).is_symlink():
        raise ValueError(f"path must not be a symlink: {path or _PYTEST_OBS_WORK_ROOT}")
    if target != root:
        raise ValueError(f"path must be the exact pytest obs work root: {root}")
    if target.exists():
        shutil.rmtree(target)


def workspace_semver(cargo_toml: Path | None = None) -> str:
    """Read [workspace.package].version from the root Cargo.toml."""
    path = cargo_toml or (_REPO_ROOT / "Cargo.toml")
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return str(data["workspace"]["package"]["version"])


def obs_package_name(env_path: Path | None = None) -> str:
    """Read OBS_PACKAGE from obs-project.env."""
    path = env_path or _OBS_ENV
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "OBS_PACKAGE":
            return value.strip()
    raise ValueError(f"OBS_PACKAGE is missing in {path}")


def obs_enabled_build_repositories(repo_root: Path | None = None) -> tuple[str, ...]:
    """Derive enabled OBS build repositories from committed _meta files."""
    from scripts.obs_repositories import load_enabled_build_repositories

    root = repo_root or _REPO_ROOT
    return load_enabled_build_repositories(root)


def obs_changes_version_marker(version: str) -> str:
    """Return the version token used in OBS .changes entry headers."""
    return f" - {version}\n"


def top_obs_changes_version(changes_text: str) -> str | None:
    """Return the version from the newest .changes entry header."""
    stripped = changes_text.lstrip("\n")
    if not stripped:
        return None
    header_block = stripped.split("-------------------------------------------------------------------\n", 2)
    if len(header_block) < 2:
        return None
    for line in header_block[1].splitlines():
        match = _CHANGES_HEADER_VERSION_RE.search(line)
        if match:
            return match.group(1)
    return None


def obs_dry_run_work_dir(test_key: str) -> Path:
    """Staging directory for OBS dry-run tests that run ``cargo vendor``.

    Uses ``target/pytest-obs-work/`` under the repo instead of pytest's default
    ``tmp_path`` (often ``/tmp``) so vendoring is less likely to hit disk quotas.
    """
    safe_key = re.sub(r"[^\w.-]+", "_", test_key).strip("_") or "obs-work"
    worker = _pytest_worker_segment()
    work = _PYTEST_OBS_WORK_ROOT / worker / safe_key
    if work.exists():
        safe_rmtree_obs_work(work)
    work.mkdir(parents=True)
    return work
