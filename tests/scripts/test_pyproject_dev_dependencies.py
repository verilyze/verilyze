# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: pyproject.toml dev deps and Makefile venv bootstrap (SSOT)."""

import re
import tomllib
from pathlib import Path

from tests.scripts.repo_root import repo_root


# CVE-2025-71176 remediation floor (GHSA-6w46-j5rx-g56g).
PYTEST_MIN_FLOOR = (9, 0, 3)

EXPECTED_DEV_PACKAGES = frozenset(
    {
        "pytest",
        "pytest-cov",
        "black",
        "pylint",
        "mypy",
        "bandit",
        "codespell",
    }
)

_FLOOR_RE = re.compile(r"^([a-zA-Z0-9_-]+)\s*>=\s*([\d.]+)\s*$")


def _load_pyproject() -> dict:
    return tomllib.loads((repo_root() / "pyproject.toml").read_text(encoding="utf-8"))


def _parse_floor(spec: str) -> tuple[str, tuple[int, ...]]:
    match = _FLOOR_RE.match(spec.strip())
    if not match:
        raise ValueError(f"expected NAME>=VERSION floor, got {spec!r}")
    name = match.group(1)
    version = tuple(int(part) for part in match.group(2).split("."))
    return name, version


def _dev_dep_floors() -> dict[str, tuple[int, ...]]:
    data = _load_pyproject()
    dev = data.get("project", {}).get("optional-dependencies", {}).get("dev", [])
    return dict(_parse_floor(spec) for spec in dev)


def _makefile_target_recipe(makefile_text: str, target_suffix: str) -> str:
    lines = makefile_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.endswith(target_suffix) and line.startswith("$("):
            start = i
            break
    if start is None:
        raise AssertionError(f"Makefile has no target ending with {target_suffix!r}")

    recipe: list[str] = []
    i = start + 1
    while i < len(lines) and lines[i].startswith("\t"):
        recipe.append(lines[i])
        i += 1
    if not recipe:
        raise AssertionError(f"target {target_suffix!r} has no recipe")
    return "\n".join(recipe)


def test_pyproject_has_build_system() -> None:
    data = _load_pyproject()
    build = data.get("build-system", {})
    assert build.get("build-backend") == "setuptools.build_meta"
    requires = build.get("requires", [])
    assert any(str(req).startswith("setuptools") for req in requires)


def test_dev_optional_dependencies_have_version_floors() -> None:
    floors = _dev_dep_floors()
    assert set(floors) == EXPECTED_DEV_PACKAGES


def test_pytest_floor_remediates_cve_2025_71176() -> None:
    floors = _dev_dep_floors()
    assert floors["pytest"] >= PYTEST_MIN_FLOOR


def test_makefile_venv_test_installs_from_pyproject_dev_extra() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    recipe = _makefile_target_recipe(text, "/bin/pytest:")
    assert 'pip install ".[dev]"' in recipe
    assert 'cd "$(MKFILE_DIR)"' in recipe
    assert "pip install pytest" not in recipe
    assert "codespell" in recipe
    assert "coverage.__file__" in recipe
    assert "htmlfiles" in recipe
    assert "PIP_TMPDIR" in recipe
    assert "LINT_PYTHON_PACKAGES" not in recipe


def test_makefile_venv_lint_installs_from_pyproject_dev_extra() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    recipe = _makefile_target_recipe(text, "/bin/black:")
    assert 'pip install ".[dev]"' in recipe
    assert 'cd "$(MKFILE_DIR)"' in recipe
    assert "pip install black" not in recipe
    assert "codespell" in recipe
    assert "LINT_PYTHON_PACKAGES" not in text


def test_makefile_has_no_lint_python_packages_variable() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "LINT_PYTHON_PACKAGES" not in text


def test_reuse_toml_annotates_pip_egg_info() -> None:
    """pip install \".[dev]\" creates *.egg-info; REUSE must not require headers."""
    text = (repo_root() / "REUSE.toml").read_text(encoding="utf-8")
    assert 'path = "**/*.egg-info/**"' in text
