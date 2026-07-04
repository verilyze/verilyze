# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Locate the verilyze repository root for script tests."""

import tomllib
from pathlib import Path

_CARGO_MARKER = "Cargo.toml"
_CONFIG_EXAMPLE_MARKER = "verilyze.conf.example"
_VERILYZE_REPO_SNIPPET = "verilyze -- workspace root"
_REPO_ROOT: Path | None = None


def _is_verilyze_repo_root(candidate: Path) -> bool:
    cargo_path = candidate / _CARGO_MARKER
    if not cargo_path.is_file():
        return False
    if not (candidate / _CONFIG_EXAMPLE_MARKER).is_file():
        return False
    cargo_text = cargo_path.read_text(encoding="utf-8")
    if _VERILYZE_REPO_SNIPPET in cargo_text:
        return True
    try:
        data = tomllib.loads(cargo_text)
    except tomllib.TOMLDecodeError:
        return False
    repository = str(data.get("workspace", {}).get("package", {}).get("repository", ""))
    return "verilyze/verilyze" in repository


def find_repo_root(start: Path | None = None) -> Path:
    """Walk parents from ``start`` until the verilyze repo root is found."""
    anchor = (start or Path(__file__)).resolve()
    if anchor.is_file():
        anchor = anchor.parent
    for parent in (anchor, *anchor.parents):
        if _is_verilyze_repo_root(parent):
            return parent
    raise RuntimeError(
        "repository root not found (no verilyze markers at or above "
        f"{anchor})"
    )


def repo_root() -> Path:
    """Return the cached repository root."""
    global _REPO_ROOT
    if _REPO_ROOT is None:
        _REPO_ROOT = find_repo_root()
    return _REPO_ROOT
