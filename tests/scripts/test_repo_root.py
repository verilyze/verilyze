# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for repository root discovery."""

from pathlib import Path

import pytest

from tests.scripts.repo_root import find_repo_root, repo_root


def test_repo_root_contains_cargo_toml() -> None:
    root = repo_root()
    assert (root / "Cargo.toml").is_file()
    assert (root / "tests" / "scripts").is_dir()


def test_find_repo_root_from_scripts_directory() -> None:
    start = repo_root() / "tests" / "scripts"
    assert find_repo_root(start) == repo_root()


def test_find_repo_root_from_file_path() -> None:
    start = repo_root() / "tests" / "scripts" / "repo_root.py"
    assert find_repo_root(start) == repo_root()


def test_find_repo_root_raises_when_marker_missing(tmp_path: Path) -> None:
    empty = tmp_path / "empty-tree"
    empty.mkdir()
    with pytest.raises(RuntimeError, match="verilyze markers"):
        find_repo_root(empty)


def test_find_repo_root_rejects_cargo_without_verilyze_markers(tmp_path: Path) -> None:
    fake = tmp_path / "fake-rust-project"
    fake.mkdir()
    (fake / "Cargo.toml").write_text('[package]\nname = "other"\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="verilyze markers"):
        find_repo_root(fake)


def test_find_repo_root_rejects_cargo_without_config_example(tmp_path: Path) -> None:
    fake = tmp_path / "partial"
    fake.mkdir()
    (fake / "Cargo.toml").write_text(
        "# verilyze -- workspace root\n[workspace]\nmembers = []\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="verilyze markers"):
        find_repo_root(fake)
