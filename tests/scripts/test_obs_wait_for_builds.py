# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS build wait helper."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_WAIT_SCRIPT = _ROOT / "scripts" / "obs-wait-for-builds.sh"
_STATUS_MODULE = _ROOT / "scripts" / "obs_wait_build_status.py"

_spec = importlib.util.spec_from_file_location(
    "obs_wait_build_status", _STATUS_MODULE
)
assert _spec is not None and _spec.loader is not None
obs_wait_build_status = importlib.util.module_from_spec(_spec)
sys.modules["obs_wait_build_status"] = obs_wait_build_status
_spec.loader.exec_module(obs_wait_build_status)

_SUCCEEDED_XML = """\
<resultlist>
  <result repository="openSUSE_Tumbleweed" arch="x86_64" code="published">
    <status package="verilyze" code="succeeded"/>
  </result>
  <result repository="openSUSE_Tumbleweed" arch="aarch64" code="published">
    <status package="verilyze" code="succeeded"/>
  </result>
  <result repository="Fedora_44" arch="x86_64" code="published">
    <status package="verilyze" code="succeeded"/>
  </result>
</resultlist>
"""

_BUILDING_XML = """\
<resultlist>
  <result repository="openSUSE_Tumbleweed" arch="x86_64" code="building">
    <status package="verilyze" code="building"/>
  </result>
  <result repository="Fedora_44" arch="x86_64" code="published">
    <status package="verilyze" code="succeeded"/>
  </result>
</resultlist>
"""

_FAILED_XML = """\
<resultlist>
  <result repository="openSUSE_Tumbleweed" arch="x86_64" code="published">
    <status package="verilyze" code="failed"/>
  </result>
</resultlist>
"""

_WAIT_REPOS = ("openSUSE_Tumbleweed", "Fedora_44")


def test_evaluate_build_results_all_succeeded() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _SUCCEEDED_XML,
        package="verilyze",
        repositories=_WAIT_REPOS,
    )
    assert summary.all_succeeded is True
    assert summary.any_failed is False
    assert summary.pending == 0


def test_evaluate_build_results_still_building() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _BUILDING_XML,
        package="verilyze",
        repositories=_WAIT_REPOS,
    )
    assert summary.all_succeeded is False
    assert summary.any_failed is False
    assert summary.pending > 0


def test_evaluate_build_results_failed() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _FAILED_XML,
        package="verilyze",
        repositories=_WAIT_REPOS,
    )
    assert summary.all_succeeded is False
    assert summary.any_failed is True


def test_wait_script_dry_run(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "OBS_PROJECT=home:tpost:verilyze",
                "OBS_PACKAGE=verilyze",
                "OBS_WAIT_REPOSITORIES=openSUSE_Tumbleweed,Fedora_44",
                "OBS_WAIT_TIMEOUT_SECONDS=120",
                "OBS_WAIT_POLL_INTERVAL_SECONDS=5",
                "",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    for key in ("OBS_USER", "OBS_PASSWORD", "OSC_USERNAME", "OSC_PASSWORD"):
        env.pop(key, None)
    proc = subprocess.run(
        [
            str(_WAIT_SCRIPT),
            "--config",
            str(env_file),
            "--version",
            "0.2.3",
            "--dry-run",
        ],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "dry-run" in output.lower()
    assert "openSUSE_Tumbleweed" in output
    assert "Fedora_44" in output


def test_wait_script_with_results_file_succeeds(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "OBS_PROJECT=home:tpost:verilyze",
                "OBS_PACKAGE=verilyze",
                "OBS_WAIT_REPOSITORIES=openSUSE_Tumbleweed,Fedora_44",
                "",
            ]
        ),
        encoding="utf-8",
    )
    results_file = tmp_path / "results.xml"
    results_file.write_text(_SUCCEEDED_XML, encoding="utf-8")
    proc = subprocess.run(
        [
            str(_WAIT_SCRIPT),
            "--config",
            str(env_file),
            "--version",
            "0.2.3",
            "--results-file",
            str(results_file),
        ],
        cwd=_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "OBS builds succeeded" in output


def test_wait_script_requires_wait_repositories(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "OBS_PROJECT=home:tpost:verilyze\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            str(_WAIT_SCRIPT),
            "--config",
            str(env_file),
            "--version",
            "0.2.3",
            "--dry-run",
        ],
        cwd=_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "OBS_WAIT_REPOSITORIES" in proc.stderr + proc.stdout
