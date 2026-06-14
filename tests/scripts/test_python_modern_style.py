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


def test_banned_typing_names_include_legacy_aliases() -> None:
    assert "List" in BANNED_TYPING_NAMES
    assert "Optional" in BANNED_TYPING_NAMES
    assert "Any" not in BANNED_TYPING_NAMES


def test_typing_extensions_redirect_includes_self() -> None:
    assert "Self" in TYPING_EXTENSIONS_REDIRECT_TO_TYPING


def test_repo_has_no_modern_style_violations() -> None:
    violations = find_violations(_ROOT)
    assert violations == []
