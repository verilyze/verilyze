# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/lib/safe-rm.sh."""

import subprocess
from pathlib import Path

import pytest

from tests.scripts.repo_root import repo_root

_SAFE_RM = repo_root() / "scripts" / "lib" / "safe-rm.sh"


def _run_safe_rm_rf(path: str, label: str = "test path") -> subprocess.CompletedProcess[str]:
    script = (
        f'REPO_ROOT="{repo_root()}"; '
        f'source "{_SAFE_RM}"; '
        f'safe_rm_rf "{path}" "{label}"'
    )
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("", "empty path"),
        ("/vendor-build", "shallow path"),
        ("/", "root path"),
    ],
)
def test_safe_rm_rf_rejects_unsafe_paths(path: str, label: str) -> None:
    proc = _run_safe_rm_rf(path, label)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "ERROR" in proc.stderr


def test_safe_rm_rf_removes_existing_directory_under_tmp(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir"
    target.mkdir(parents=True)
    marker = target / "file.txt"
    marker.write_text("x", encoding="utf-8")
    proc = _run_safe_rm_rf(str(target), "tmp nested dir")
    assert proc.returncode == 0, proc.stderr
    assert not target.exists()


def test_safe_rm_rf_rejects_symlink_target(tmp_path: Path) -> None:
    real = tmp_path / "nested" / "dir"
    real.mkdir(parents=True)
    (real / "keep.txt").write_text("x", encoding="utf-8")
    link = tmp_path / "linked-dir"
    link.symlink_to(real)
    proc = _run_safe_rm_rf(str(link), "symlink dir")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "symlink" in proc.stderr.lower()
    assert real.is_dir()
    assert (real / "keep.txt").is_file()
