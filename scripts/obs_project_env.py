#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Parse packaging/obs/obs-project.env for automation scripts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ObsProjectEnv:
    """OBS project coordinates and packaging constants."""

    obs_project: str
    obs_package: str
    obs_spec_filename: str
    obs_changes_filename: str
    obs_legacy_changes_filename: str
    obs_maintainer: str


def _trim(value: str) -> str:
    trimmed = value.strip()
    if len(trimmed) >= 2 and trimmed[0] == '"' and trimmed[-1] == '"':
        return trimmed[1:-1]
    return trimmed


def parse_obs_project_env(env_path: Path) -> ObsProjectEnv:
    """Load OBS coordinate and packaging constants from obs-project.env."""
    if not env_path.is_file():
        raise FileNotFoundError(f"OBS config file not found: {env_path}")

    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = _trim(raw_line)
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key = _trim(key)
        if not key:
            continue
        values[key] = _trim(value)

    required = ("OBS_PROJECT", "OBS_PACKAGE")
    missing = [key for key in required if not values.get(key)]
    if missing:
        joined = ", ".join(missing)
        msg = f"Missing required OBS config keys in {env_path}: {joined}"
        raise ValueError(msg)

    return ObsProjectEnv(
        obs_project=values["OBS_PROJECT"],
        obs_package=values["OBS_PACKAGE"],
        obs_spec_filename=values.get("OBS_SPEC_FILENAME", "verilyze.spec"),
        obs_changes_filename=values.get(
            "OBS_CHANGES_FILENAME",
            "verilyze.changes",
        ),
        obs_legacy_changes_filename=values.get(
            "OBS_LEGACY_CHANGES_FILENAME",
            "verilyze.spec.changes",
        ),
        obs_maintainer=values.get(
            "OBS_MAINTAINER",
            "Travis Post <post.travis@gmail.com>",
        ),
    )
