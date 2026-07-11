# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: fuzz-changed must not depend on debug (lazy AFL skip before bootstrap)."""

from pathlib import Path

import pytest

from tests.scripts.repo_root import repo_root
from tests.scripts.test_makefile_check_includes_deny import _extract_prerequisite_block


@pytest.mark.parametrize(
    "target",
    ("fuzz-changed", "fuzz-extended"),
)
def test_lazy_fuzz_targets_do_not_depend_on_debug(target: str) -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, target)
    assert "debug" not in block.split(), (
        f"make {target} must not depend on debug; fuzz.sh skips before AFL when "
        "no mapped files changed"
    )


def test_fuzz_target_has_no_debug_prerequisite() -> None:
    """make fuzz runs AFL for all targets; still no debug dep (cargo afl build suffices)."""
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "fuzz")
    assert "debug" not in block.split()
