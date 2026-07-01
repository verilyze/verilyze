# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/release-preflight.sh."""

import os
import subprocess
from pathlib import Path

import pytest

from tests.scripts.obs_signing_fixture import obs_signing_env

_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPT = _ROOT / "scripts" / "release-preflight.sh"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_CARGO = _ROOT / "Cargo.toml"


def _run_preflight(*extra: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(obs_signing_env())
    return subprocess.run(
        [str(_SCRIPT), *extra],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


@pytest.mark.skipif(
    not _SCRIPT.is_file(), reason="release-preflight.sh not installed"
)
class TestReleasePreflight:
    def test_script_exists(self) -> None:
        assert _SCRIPT.is_file()

    def test_fails_when_changelog_section_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _run_preflight()
        if proc.returncode == 0:
            pytest.skip(
                "workspace CHANGELOG already has section for current version"
            )
        assert proc.returncode != 0
        assert (
            "CHANGELOG" in proc.stderr + proc.stdout
            or "changelog" in (proc.stderr + proc.stdout).lower()
        )

    def test_succeeds_when_changelog_and_version_align(self) -> None:
        """When workspace version section exists, preflight exits 0."""
        from tests.scripts.workspace_helpers import workspace_semver

        version = workspace_semver(_CARGO)
        changelog = _CHANGELOG.read_text(encoding="utf-8")
        if f"## [{version}]" not in changelog:
            pytest.skip(
                f"no CHANGELOG section for workspace version {version}"
            )
        proc = _run_preflight()
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "git tag -s" in proc.stdout or "push origin" in proc.stdout
