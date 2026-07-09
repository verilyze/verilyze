# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Subprocess exit-code smoke tests (DOC-004, FR-010)."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.scripts.repo_root import repo_root

EXIT_CODE_UNKNOWN_PROVIDER = 2
EXIT_CODE_OFFLINE_CACHE_MISS = 4


def _resolve_vlz_bin() -> Path:
    env_bin = os.environ.get("VLZ_BIN")
    if env_bin:
        candidate = Path(env_bin)
        if candidate.is_file():
            return candidate
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=repo_root(),
        check=True,
        capture_output=True,
        text=True,
    )
    import json

    target_dir = Path(json.loads(proc.stdout)["target_directory"])
    for sub in ("release", "debug"):
        candidate = target_dir / sub / "vlz"
        if candidate.is_file():
            return candidate
    raise RuntimeError("vlz binary not found; run make release or set VLZ_BIN")


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
        vlz = _resolve_vlz_bin()
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

    def test_offline_cache_miss_exits_4(self) -> None:
        vlz = _resolve_vlz_bin()
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
