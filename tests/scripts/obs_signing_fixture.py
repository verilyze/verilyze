# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Offline OBS signing keys fixture for subprocess tests."""

from pathlib import Path

VLZ_OBS_SIGNING_KEYS_FILE = "VLZ_OBS_SIGNING_KEYS_FILE"

_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "obs_signing_keys.html"
)


def obs_signing_fixture_path() -> Path:
    """Return path to committed OBS signing keys HTML fixture."""
    return _FIXTURE


def obs_signing_env() -> dict[str, str]:
    """Return env vars that skip live OBS signing key HTTP fetches."""
    return {VLZ_OBS_SIGNING_KEYS_FILE: str(obs_signing_fixture_path())}
