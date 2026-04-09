# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: make -j check must not run fuzz-changed and coverage-quick in parallel."""

import re
from pathlib import Path

from tests.scripts.test_makefile_check_includes_deny import _extract_prerequisite_block


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_check_lists_fuzz_then_coverage_not_separate_fuzz_and_coverage() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "check")
    tokens = block.replace("\\", " ").split()
    assert "fuzz-then-coverage" in tokens, (
        "make check must depend on fuzz-then-coverage so cargo afl and "
        "cargo llvm-cov do not run in parallel under make -j"
    )
    assert "fuzz-changed" not in tokens
    assert "coverage-quick" not in tokens


def test_check_slow_lists_fuzz_then_coverage() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "check-slow")
    tokens = block.replace("\\", " ").split()
    assert "fuzz-then-coverage" in tokens
    assert "fuzz-changed" not in tokens
    assert "coverage-quick" not in tokens


def test_fuzz_then_coverage_target_runs_make_fuzz_changed_then_coverage_quick() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert re.search(
        r"^fuzz-then-coverage:\n\t\$\(MAKE\) fuzz-changed\n\t\$\(MAKE\) coverage-quick",
        text,
        re.MULTILINE,
    ), "fuzz-then-coverage must run fuzz-changed then coverage-quick sequentially"
