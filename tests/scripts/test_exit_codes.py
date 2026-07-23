# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Subprocess exit-code smoke tests (DOC-004, FR-010)."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.scripts.workspace_helpers import resolve_vlz_bin_for_tests

EXIT_CODE_UNKNOWN_PROVIDER = 2
EXIT_CODE_RESOLUTION_FAILED = 4
EXIT_CODE_OFFLINE_CACHE_MISS = 6


def _xdg_env(tmp: Path) -> dict[str, str]:
    base = str(tmp)
    return {
        "XDG_CACHE_HOME": base,
        "XDG_DATA_HOME": base,
        "XDG_CONFIG_HOME": base,
    }


class TestExitCodesSubprocess:
    """Scripted scenarios that spawn the vlz binary (DOC-004)."""

    def test_unknown_provider_exits_2(self) -> None:
        vlz = resolve_vlz_bin_for_tests()
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, **_xdg_env(Path(tmp) / "xdg")}
            proc = subprocess.run(
                [
                    str(vlz),
                    "scan",
                    tmp,
                    "--provider",
                    "nonexistentprovider",
                    "--offline",
                ],
                env=env,
                check=False,
            )
            assert proc.returncode == EXIT_CODE_UNKNOWN_PROVIDER

    def test_resolution_failed_exits_4(self) -> None:
        vlz = resolve_vlz_bin_for_tests()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project\nname = broken\n",
                encoding="utf-8",
            )
            env = {**os.environ, **_xdg_env(root / "xdg")}
            proc = subprocess.run(
                [str(vlz), "scan", str(root)],
                env=env,
                check=False,
            )
            assert proc.returncode == EXIT_CODE_RESOLUTION_FAILED

    def test_offline_cache_miss_exits_6(self) -> None:
        vlz = resolve_vlz_bin_for_tests()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("pkg==1.0\n", encoding="utf-8")
            env = {**os.environ, **_xdg_env(root / "xdg")}
            proc = subprocess.run(
                [str(vlz), "scan", str(root), "--offline"],
                env=env,
                check=False,
            )
            assert proc.returncode == EXIT_CODE_OFFLINE_CACHE_MISS
