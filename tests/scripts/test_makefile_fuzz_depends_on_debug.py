# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: fuzz targets must depend on debug before AFL bootstrap (parallel -j check)."""

from pathlib import Path

import pytest

from tests.scripts.test_makefile_check_includes_deny import _extract_prerequisite_block


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


@pytest.mark.parametrize(
    "target",
    ("fuzz", "fuzz-changed", "fuzz-extended"),
)
def test_fuzz_target_depends_on_debug(target: str) -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, target)
    assert "debug" in block.split(), (
        f"make {target} must depend on debug so AFL is not bootstrapped alongside "
        "the main cargo build under make -j check"
    )
