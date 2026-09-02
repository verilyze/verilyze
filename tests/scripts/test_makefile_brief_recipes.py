# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: check-reachable Makefile recipes stay quiet in brief CI mode."""

from tests.scripts.makefile_graph import (
    CHECK_ROOTS,
    find_brief_recipe_violations,
    parse_makefile,
    walk_check_reachable,
)
from tests.scripts.repo_root import repo_root


def test_check_roots_include_parallel_gates() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    reachable = walk_check_reachable(parse_makefile(text))
    for gate in ("check-parallel", "check-fast-parallel", "fuzz-then-coverage"):
        assert gate in reachable, f"{gate} must be reachable from {CHECK_ROOTS}"


def test_check_reachable_recipes_are_brief_safe() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    violations = find_brief_recipe_violations(text)
    if not violations:
        return
    lines = [
        "check-reachable Makefile recipes must use @ and $(MAKE_RUN_LEAF) "
        "for tool commands (see CONTRIBUTING CI check debug output):"
    ]
    for item in violations:
        lines.append(f"  - {item.target}: {item.reason}")
        lines.append(f"    recipe: {item.recipe[:120]}")
    raise AssertionError("\n".join(lines))
