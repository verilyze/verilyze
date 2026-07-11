# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/lib/fuzz-resolve-targets.sh change detection."""

import os
import subprocess
from pathlib import Path

import pytest

from tests.scripts.repo_root import repo_root

_RESOLVE = repo_root() / "scripts" / "lib" / "fuzz-resolve-targets.sh"
_FUZZ_SH = repo_root() / "scripts" / "fuzz.sh"
_MAP = repo_root() / "scripts" / "fuzz-targets.map"


def _run_resolve(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_RESOLVE), *args],
        cwd=cwd or repo_root(),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "FUZZ_TARGETS_FILE": str(_MAP)},
    )


def test_resolve_changed_dry_run_skip_when_no_diff(monkeypatch: pytest.MonkeyPatch) -> None:
    """When HEAD matches base, --changed --dry-run prints SKIP."""
    proc = _run_resolve("--changed", "--dry-run")
    assert proc.returncode == 0
    if proc.stdout.strip() == "SKIP":
        assert "skipping fuzz" in proc.stderr.lower()
    else:
        assert proc.stdout.startswith("RUN:")


def test_fuzz_sh_changed_dry_run_exits_before_afl_markers() -> None:
    """fuzz.sh --changed --dry-run must not reference cargo afl build in output."""
    proc = subprocess.run(
        ["bash", str(_FUZZ_SH), "--changed", "--dry-run"],
        cwd=repo_root(),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "FUZZ_TARGETS_FILE": str(_MAP)},
    )
    assert proc.returncode == 0
    out = proc.stdout.strip()
    assert out in ("SKIP",) or out.startswith("RUN:")
    combined = proc.stdout + proc.stderr
    assert "cargo afl build" not in combined
    assert "cargo afl config" not in combined


def test_fuzz_sh_sources_resolve_library() -> None:
    text = _FUZZ_SH.read_text(encoding="utf-8")
    assert "fuzz-resolve-targets.sh" in text
    assert "fuzz_resolve_changed_targets" in text


def test_resolve_all_includes_config_toml() -> None:
    proc = _run_resolve("--all", "--dry-run")
    assert proc.returncode == 0
    assert proc.stdout.startswith("RUN:")
    assert "config_toml" in proc.stdout


def test_resolve_targets_filter() -> None:
    proc = _run_resolve("--targets=config_toml", "--dry-run")
    assert proc.returncode == 0
    assert proc.stdout.strip() == "RUN:config_toml"
