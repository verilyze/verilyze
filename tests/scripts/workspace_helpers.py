# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared version and OBS constants for script tests (DRY with Cargo.toml)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_OBS_ENV = _REPO_ROOT / "packaging" / "obs" / "obs-project.env"
_CHANGES_HEADER_VERSION_RE = re.compile(r" - (\d+\.\d+\.\d+)\s*$")


def repo_root() -> Path:
    return _REPO_ROOT


def workspace_semver(cargo_toml: Path | None = None) -> str:
    """Read [workspace.package].version from the root Cargo.toml."""
    path = cargo_toml or (_REPO_ROOT / "Cargo.toml")
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return str(data["workspace"]["package"]["version"])


def obs_package_name(env_path: Path | None = None) -> str:
    """Read OBS_PACKAGE from obs-project.env."""
    path = env_path or _OBS_ENV
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "OBS_PACKAGE":
            return value.strip()
    raise ValueError(f"OBS_PACKAGE is missing in {path}")


def obs_changes_version_marker(version: str) -> str:
    """Return the version token used in OBS .changes entry headers."""
    return f" - {version}\n"


def top_obs_changes_version(changes_text: str) -> str | None:
    """Return the version from the newest .changes entry header."""
    stripped = changes_text.lstrip("\n")
    if not stripped:
        return None
    header_block = stripped.split("-------------------------------------------------------------------\n", 2)
    if len(header_block) < 2:
        return None
    for line in header_block[1].splitlines():
        match = _CHANGES_HEADER_VERSION_RE.search(line)
        if match:
            return match.group(1)
    return None
