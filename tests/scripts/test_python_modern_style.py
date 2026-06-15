# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for Python 3.11+ modern style enforcement."""

from pathlib import Path

import pytest

from scripts.python_modern_style import (
    BANNED_TYPING_NAMES,
    TYPING_EXTENSIONS_REDIRECT_TO_TYPING,
    find_violations,
    find_violations_in_source,
)

_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.parametrize(
    ("source", "expected_substring"),
    [
        ("from __future__ import annotations\n", "future-import"),
        ("from typing import List\n", "legacy-typing"),
        ("import typing\nx: typing.Optional[str] = None\n", "legacy-typing"),
        ("from typing_extensions import Self\n", "typing-extensions"),
        ("import typing_extensions as typing_ext\nx = typing_ext.Self\n", "typing-extensions"),
    ],
)
def test_find_violations_in_source_flags_banned_patterns(
    source: str, expected_substring: str
) -> None:
    violations = find_violations_in_source(source, path=Path("example.py"))
    assert violations
    assert expected_substring in violations[0]


@pytest.mark.parametrize(
    "source",
    [
        "from typing import Any, TypedDict, cast\n",
        "from pathlib import Path\n\ndef f(x: str | None) -> dict[str, str]:\n    return {}\n",
    ],
)
def test_find_violations_in_source_allows_modern_patterns(source: str) -> None:
    assert find_violations_in_source(source, path=Path("example.py")) == []


def test_find_violations_collects_from_iterated_files(
    tmp_path: Path, monkeypatch
) -> None:
    from scripts import python_modern_style

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    good = scripts_dir / "good.py"
    good.write_text("x: str | None = None\n", encoding="utf-8")

    monkeypatch.setattr(python_modern_style, "iter_python_files", lambda _r: [good])
    assert find_violations(tmp_path) == []


def test_banned_typing_names_include_legacy_aliases() -> None:
    assert "List" in BANNED_TYPING_NAMES
    assert "Optional" in BANNED_TYPING_NAMES
    assert "Any" not in BANNED_TYPING_NAMES


def test_typing_extensions_redirect_includes_self() -> None:
    assert "Self" in TYPING_EXTENSIONS_REDIRECT_TO_TYPING


def test_repo_has_no_modern_style_violations() -> None:
    violations = find_violations(_ROOT)
    assert violations == []


def test_main_returns_zero_when_clean() -> None:
    from scripts.python_modern_style import main

    assert main() == 0


def test_main_returns_one_when_violations_exist(monkeypatch) -> None:
    from scripts.python_modern_style import main

    monkeypatch.setattr(
        "scripts.python_modern_style.find_violations",
        lambda _root: ["example.py:1: future-import"],
    )
    assert main() == 1


def test_iter_python_files_skips_missing_directories(tmp_path: Path) -> None:
    from scripts.python_modern_style import iter_python_files

    assert iter_python_files(tmp_path) == []


def test_find_violations_reports_read_errors(tmp_path: Path, monkeypatch) -> None:
    from scripts import python_modern_style

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    bad = scripts_dir / "bad.py"
    bad.write_text("x = 1\n", encoding="utf-8")

    def fake_iter(_root: Path) -> list[Path]:
        return [bad]

    def fake_read_text(self, encoding="utf-8"):  # noqa: ANN001, ARG001
        raise OSError("read failed")

    monkeypatch.setattr(python_modern_style, "iter_python_files", fake_iter)
    monkeypatch.setattr(Path, "read_text", fake_read_text)
    messages = find_violations(tmp_path)
    assert messages
    assert "read-error" in messages[0]


def test_main_module_exits_zero() -> None:
    import runpy
    import sys

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(
            str(_ROOT / "scripts" / "python_modern_style.py"),
            run_name="__main__",
        )
    assert exc_info.value.code == 0
