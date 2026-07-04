# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/pre-commit-protected-files.sh."""

import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_PROTECTED_FILES_SCRIPT = (
    repo_root() / "scripts" / "pre-commit-protected-files.sh"
)
_PROTECTED_PATH = "LICENSE"


def _run_protected_files_check(cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_PROTECTED_FILES_SCRIPT)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _init_git_repo(path: Path) -> None:
    subprocess.run(
        ["git", "init", "-q"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test User",
            "commit",
            "--allow-empty",
            "-m",
            "init",
        ],
        cwd=path,
        check=True,
    )


def test_passes_when_no_protected_files_staged(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)

    proc = _run_protected_files_check(tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_passes_when_protected_file_not_staged(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / _PROTECTED_PATH).write_text("gpl\n", encoding="utf-8")

    proc = _run_protected_files_check(tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_fails_when_protected_file_staged(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    license_path = tmp_path / _PROTECTED_PATH
    license_path.write_text("gpl\n", encoding="utf-8")
    subprocess.run(["git", "add", _PROTECTED_PATH], cwd=tmp_path, check=True)

    proc = _run_protected_files_check(tmp_path)

    assert proc.returncode != 0
    assert _PROTECTED_PATH in proc.stderr
    assert "protected" in proc.stderr.lower()
    assert "CONTRIBUTING" in proc.stderr


def test_fails_when_protected_file_modified_and_staged(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    license_path = tmp_path / _PROTECTED_PATH
    license_path.write_text("original\n", encoding="utf-8")
    subprocess.run(["git", "add", _PROTECTED_PATH], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test User",
            "commit",
            "-m",
            "add license",
        ],
        cwd=tmp_path,
        check=True,
    )
    license_path.write_text("modified\n", encoding="utf-8")
    subprocess.run(["git", "add", _PROTECTED_PATH], cwd=tmp_path, check=True)

    proc = _run_protected_files_check(tmp_path)

    assert proc.returncode != 0
    assert _PROTECTED_PATH in proc.stderr
