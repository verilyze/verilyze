# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: .venv-test bootstrap must verify pytest works (stale CI cache)."""

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _venv_test_pytest_recipe(makefile_text: str) -> str:
    """Return tab-indented recipe lines for the $(VENV_TEST)/bin/pytest target."""
    lines = makefile_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.endswith("/bin/pytest:") and "VENV_TEST" in line:
            start = i
            break
    if start is None:
        raise AssertionError("Makefile has no $(VENV_TEST)/bin/pytest target")

    recipe: list[str] = []
    i = start + 1
    while i < len(lines) and lines[i].startswith("\t"):
        recipe.append(lines[i])
        i += 1
    if not recipe:
        raise AssertionError("$(VENV_TEST)/bin/pytest has no recipe")
    return "\n".join(recipe)


def test_venv_test_pytest_recipe_health_checks_before_bootstrap() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    recipe = _venv_test_pytest_recipe(text)
    assert "-m pytest --version" in recipe, (
        ".venv-test must run python -m pytest --version before trusting cache"
    )
    assert "rm -rf $(VENV_TEST)" in recipe, (
        ".venv-test must remove broken venv before recreate"
    )
