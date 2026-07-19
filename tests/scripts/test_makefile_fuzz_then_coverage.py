# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: make -j check must not run fuzz-changed and coverage-quick in parallel."""

import re
from pathlib import Path

from tests.scripts.repo_root import repo_root
from tests.scripts.test_makefile_check_includes_deny import _extract_prerequisite_block


def test_check_lists_fuzz_then_coverage_not_separate_fuzz_and_coverage() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert re.search(
        r"^check: setup\n\t@\$\(MAKE\) check-headers\n"
        r"\t@\$\(MAKE\) --output-sync=target -k -j check-parallel\n"
        r"\t@\$\(MAKE\) fuzz-then-coverage",
        text,
        re.MULTILINE,
    ), (
        "make check must run fuzz-then-coverage after parallel gates so "
        "cargo llvm-cov does not race clippy or cargo build under target/"
    )
    parallel = _extract_prerequisite_block(text, "check-parallel")
    parallel_tokens = parallel.replace("\\", " ").split()
    assert "fuzz-then-coverage" not in parallel_tokens
    assert "fuzz-changed" not in parallel_tokens
    assert "coverage-quick" not in parallel_tokens


def test_check_slow_lists_fuzz_then_coverage() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "check-slow")
    tokens = block.replace("\\", " ").split()
    assert "fuzz-then-coverage" in tokens
    assert "fuzz-changed" not in tokens
    assert "coverage-quick" not in tokens


def test_fuzz_then_coverage_target_runs_make_fuzz_changed_then_coverage_quick() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert re.search(
        r"^fuzz-then-coverage:\n\t\$\(MAKE\) fuzz-changed\n\t\$\(MAKE\) coverage-quick",
        text,
        re.MULTILINE,
    ), "fuzz-then-coverage must run fuzz-changed then coverage-quick sequentially"
