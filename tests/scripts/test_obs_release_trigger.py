# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS release-trigger workflow wiring and helper script."""

import os
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_RELEASE = _ROOT / ".github" / "workflows" / "release.yml"
_OBS_SCRIPT = _ROOT / "scripts" / "obs-trigger-build.sh"


def _run_script(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )


def test_release_workflow_invokes_obs_trigger_script() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "Trigger OBS source-service refresh/build" in text
    assert "Verify OBS signing metadata" in text
    assert "./scripts/check-obs-signing.sh" in text
    assert "./scripts/obs-trigger-build.sh" in text
    assert "secrets.OBS_TOKEN" in text


def test_obs_trigger_script_dry_run_reads_project_coordinates(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "OBS_PROJECT=home:tpost:verilyze",
                "OBS_PACKAGE=verilyze",
                "",
            ]
        ),
        encoding="utf-8",
    )

    proc = _run_script(
        [
            str(_OBS_SCRIPT),
            "--config",
            str(env_file),
            "--version",
            "0.1.0",
            "--dry-run",
        ]
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    output = proc.stdout + proc.stderr
    assert "home:tpost:verilyze" in output
    assert "verilyze" in output
    assert "0.1.0" in output


def test_obs_trigger_script_rejects_missing_package_key(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text("OBS_PROJECT=home:tpost:verilyze\n", encoding="utf-8")

    proc = _run_script(
        [
            str(_OBS_SCRIPT),
            "--config",
            str(env_file),
            "--version",
            "0.1.0",
            "--dry-run",
        ]
    )

    assert proc.returncode == 1
    assert "OBS_PACKAGE" in (proc.stderr + proc.stdout)
