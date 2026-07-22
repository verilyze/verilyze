# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/check_pylock_dev.py offline validation."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_pylock_dev.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_pylock_dev", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_name_pep503() -> None:
    mod = _load_module()
    assert mod._normalize_name("PyYAML") == "pyyaml"
    assert mod._normalize_name("pytest_cov") == "pytest-cov"


def test_direct_dev_names_from_pyproject() -> None:
    mod = _load_module()
    names = mod._direct_dev_names(
        {
            "project": {
                "optional-dependencies": {
                    "dev": ["pytest>=9", "black>=26", "pytest-cov>=7"],
                }
            }
        }
    )
    assert names == {"pytest", "black", "pytest-cov"}


def test_main_ok_on_committed_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load_module()
    monkeypatch.setattr(mod, "ROOT", ROOT)
    monkeypatch.setattr(mod, "LOCK_PATH", ROOT / "pylock.dev.toml")
    monkeypatch.setattr(mod, "PYPROJECT_PATH", ROOT / "pyproject.toml")
    assert mod.main() == 0


def test_main_missing_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _load_module()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\n[project.optional-dependencies]\n'
        'dev = ["pytest>=9"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "LOCK_PATH", tmp_path / "pylock.dev.toml")
    monkeypatch.setattr(mod, "PYPROJECT_PATH", pyproject)
    assert mod.main() == 1


def test_main_missing_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _load_module()
    lock = tmp_path / "pylock.dev.toml"
    lock.write_text(
        'lock-version = "1.0"\ncreated-by = "test"\n'
        '[[packages]]\nname = "pytest"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "LOCK_PATH", lock)
    monkeypatch.setattr(mod, "PYPROJECT_PATH", tmp_path / "pyproject.toml")
    assert mod.main() == 1


def test_direct_dev_names_skips_non_string_specs() -> None:
    mod = _load_module()
    names = mod._direct_dev_names(
        {
            "project": {
                "optional-dependencies": {
                    "dev": ["pytest>=9", 42, None],
                }
            }
        }
    )
    assert names == {"pytest"}


@pytest.mark.parametrize(
    ("lock", "direct", "expected"),
    [
        ({}, {"pytest"}, "pylock.dev.toml missing lock-version"),
        (
            {"lock-version": "", "created-by": "t", "packages": [{}]},
            {"pytest"},
            "pylock.dev.toml missing lock-version",
        ),
        (
            {"lock-version": "2.0", "created-by": "t", "packages": [{}]},
            {"pytest"},
            "unsupported lock-version major 2.0",
        ),
        (
            {"lock-version": "1.0", "packages": [{"name": "pytest"}]},
            {"pytest"},
            "pylock.dev.toml missing created-by",
        ),
        (
            {"lock-version": "1.0", "created-by": "t", "packages": []},
            {"pytest"},
            "pylock.dev.toml packages must be a non-empty array",
        ),
        (
            {
                "lock-version": "1.0",
                "created-by": "t",
                "packages": ["not-a-table"],
            },
            {"pytest"},
            "package entry must be a table",
        ),
        (
            {
                "lock-version": "1.0",
                "created-by": "t",
                "packages": [{"version": "1.0"}],
            },
            {"pytest"},
            "package entry missing name",
        ),
        (
            {
                "lock-version": "1.0",
                "created-by": "t",
                "packages": [{"name": "pytest", "version": "1.0"}],
            },
            set(),
            "no direct dev dependencies in pyproject.toml",
        ),
        (
            {
                "lock-version": "1.0",
                "created-by": "t",
                "packages": [{"name": "other", "version": "1.0"}],
            },
            {"pytest"},
            "direct dev deps missing from pylock.dev.toml: pytest",
        ),
        (
            {
                "lock-version": "1.0",
                "created-by": "t",
                "packages": [{"name": "pytest", "version": "1.0"}],
            },
            {"pytest"},
            "package count 1 <= direct count 1; expected transitive packages",
        ),
    ],
)
def test_validate_lock_errors(lock: dict, direct: set[str], expected: str) -> None:
    mod = _load_module()
    assert mod._validate_lock(lock, direct) == expected


def test_validate_lock_ok() -> None:
    mod = _load_module()
    lock = {
        "lock-version": "1.0",
        "created-by": "test",
        "packages": [
            {"name": "pytest", "version": "1.0"},
            {"name": "pluggy", "version": "1.0"},
        ],
    }
    assert mod._validate_lock(lock, {"pytest"}) is None
