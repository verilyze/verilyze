#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Offline validation for committed pylock.dev.toml (PEP 751)."""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "pylock.dev.toml"
PYPROJECT_PATH = ROOT / "pyproject.toml"


def _normalize_name(name: str) -> str:
    """Normalize a distribution name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _direct_dev_names(pyproject: dict) -> set[str]:
    """Return normalized names from optional-dependencies.dev."""
    project = pyproject.get("project") or {}
    extras = project.get("optional-dependencies") or {}
    specs = extras.get("dev") or []
    names: set[str] = set()
    for spec in specs:
        if not isinstance(spec, str):
            continue
        # PEP 508: name before version ops / extras / markers
        base = re.split(r"[<>=!~;\[]", spec, maxsplit=1)[0].strip()
        if base:
            names.add(_normalize_name(base))
    return names


def _validate_lock(  # pylint: disable=too-many-return-statements
    lock: dict, direct: set[str]
) -> str | None:
    """Return an error message, or None when the lock is valid."""
    lock_version = lock.get("lock-version")
    if not isinstance(lock_version, str) or not lock_version:
        return "pylock.dev.toml missing lock-version"
    major = lock_version.split(".", maxsplit=1)[0]
    if major != "1":
        return f"unsupported lock-version major {lock_version}"

    if not isinstance(lock.get("created-by"), str) or not lock["created-by"]:
        return "pylock.dev.toml missing created-by"

    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        return "pylock.dev.toml packages must be a non-empty array"

    locked_names: set[str] = set()
    for entry in packages:
        if not isinstance(entry, dict):
            return "package entry must be a table"
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            return "package entry missing name"
        locked_names.add(_normalize_name(name))

    if not direct:
        return "no direct dev dependencies in pyproject.toml"
    missing = sorted(direct - locked_names)
    if missing:
        return "direct dev deps missing from pylock.dev.toml: " + ", ".join(
            missing
        )
    if len(packages) <= len(direct):
        return (
            f"package count {len(packages)} <= direct count {len(direct)}; "
            "expected transitive packages"
        )
    return None


def main() -> int:
    """Validate committed pylock.dev.toml; exit 0 on success, 1 on failure."""
    if not LOCK_PATH.is_file():
        print(f"ERROR: missing {LOCK_PATH}", file=sys.stderr)
        return 1
    if not PYPROJECT_PATH.is_file():
        print(f"ERROR: missing {PYPROJECT_PATH}", file=sys.stderr)
        return 1

    with PYPROJECT_PATH.open("rb") as fh:
        pyproject = tomllib.load(fh)
    with LOCK_PATH.open("rb") as fh:
        lock = tomllib.load(fh)

    err = _validate_lock(lock, _direct_dev_names(pyproject))
    if err is not None:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    packages = lock["packages"]
    direct = _direct_dev_names(pyproject)
    print(
        f"OK: {LOCK_PATH.name} lock-version={lock['lock-version']} "
        f"packages={len(packages)} direct_dev={len(direct)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
