# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS build wait helper."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.scripts.workspace_helpers import obs_enabled_build_repositories

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

_FIXTURE_XML_REPOS = frozenset({"openSUSE_Tumbleweed", "Fedora_44"})


def _fixture_wait_repositories() -> tuple[str, ...]:
    return tuple(
        repo
        for repo in obs_enabled_build_repositories()
        if repo in _FIXTURE_XML_REPOS
    )


def test_evaluate_build_results_all_succeeded() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _SUCCEEDED_XML,
        package="verilyze",
        repositories=_fixture_wait_repositories(),
    )
    assert summary.all_succeeded is True
    assert summary.any_failed is False
    assert summary.pending == 0


def test_evaluate_build_results_still_building() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _BUILDING_XML,
        package="verilyze",
        repositories=_fixture_wait_repositories(),
    )
    assert summary.all_succeeded is False
    assert summary.any_failed is False
    assert summary.pending > 0


def test_evaluate_build_results_failed() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _FAILED_XML,
        package="verilyze",
        repositories=_fixture_wait_repositories(),
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
    for repo in obs_enabled_build_repositories():
        assert repo in output


def test_wait_script_with_results_file_succeeds(tmp_path: Path) -> None:
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
    results_file = tmp_path / "results.xml"
    results_file.write_text(_SUCCEEDED_XML, encoding="utf-8")
    fixture_repos = ",".join(_fixture_wait_repositories())
    proc = subprocess.run(
        [
            str(_WAIT_SCRIPT),
            "--config",
            str(env_file),
            "--version",
            "0.2.3",
            "--repositories",
            fixture_repos,
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


def test_wait_script_requires_repository_resolution(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "OBS_PROJECT=home:tpost:verilyze\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )
    missing_meta_root = tmp_path / "empty-root"
    missing_meta_root.mkdir()
    proc = subprocess.run(
        [
            str(_WAIT_SCRIPT),
            "--config",
            str(env_file),
            "--repo-root",
            str(missing_meta_root),
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
    output = proc.stderr + proc.stdout
    assert proc.returncode == 1
    assert "project _meta" in output.lower() or "enabled obs repositories" in output.lower()


def test_evaluate_build_results_requires_repositories() -> None:
    with pytest.raises(ValueError, match="repositories must not be empty"):
        obs_wait_build_status.evaluate_build_results(
            _SUCCEEDED_XML,
            package="verilyze",
            repositories=(),
        )


def test_evaluate_build_results_skips_unknown_repository() -> None:
    summary = obs_wait_build_status.evaluate_build_results(
        _SUCCEEDED_XML,
        package="verilyze",
        repositories=("Nonexistent_Repo",),
    )
    assert summary.matched == 0
    assert summary.all_succeeded is False


def test_evaluate_build_results_pending_when_status_missing() -> None:
    xml = """\
<resultlist>
  <result repository="openSUSE_Tumbleweed" arch="x86_64">
  </result>
</resultlist>
"""
    summary = obs_wait_build_status.evaluate_build_results(
        xml,
        package="verilyze",
        repositories=("openSUSE_Tumbleweed",),
    )
    assert summary.pending == 1
    assert "openSUSE_Tumbleweed/x86_64" in summary.pending_targets[0]


def test_format_shell_summary_quotes_single_quotes() -> None:
    summary = obs_wait_build_status.BuildResultsSummary(
        all_succeeded=False,
        any_failed=True,
        pending=0,
        matched=1,
        failures=("repo/arch:failed",),
        pending_targets=(),
    )
    text = obs_wait_build_status.format_shell_summary(summary)
    assert "FAILURES='repo/arch:failed'" in text


def test_main_cli_reads_xml_file(tmp_path: Path) -> None:
    xml_file = tmp_path / "results.xml"
    xml_file.write_text(_SUCCEEDED_XML, encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(_STATUS_MODULE),
            "--package",
            "verilyze",
            "--repositories",
            "openSUSE_Tumbleweed,Fedora_44",
            "--xml-file",
            str(xml_file),
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ALL_SUCCEEDED=1" in proc.stdout


def test_evaluate_build_results_ignores_other_package_status() -> None:
    xml = """\
<resultlist>
  <result repository="openSUSE_Tumbleweed" arch="x86_64">
    <status package="other" code="failed"/>
  </result>
</resultlist>
"""
    summary = obs_wait_build_status.evaluate_build_results(
        xml,
        package="verilyze",
        repositories=("openSUSE_Tumbleweed",),
    )
    assert summary.matched == 0


def test_evaluate_build_results_unknown_status_is_pending() -> None:
    xml = """\
<resultlist>
  <result repository="openSUSE_Tumbleweed" arch="x86_64">
    <status package="verilyze" code="weird"/>
  </result>
</resultlist>
"""
    summary = obs_wait_build_status.evaluate_build_results(
        xml,
        package="verilyze",
        repositories=("openSUSE_Tumbleweed",),
    )
    assert summary.pending == 1
    assert "weird" in summary.pending_targets[0]


def test_main_cli_accepts_inline_xml() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(_STATUS_MODULE),
            "--package",
            "verilyze",
            "--repositories",
            "openSUSE_Tumbleweed",
            "--xml",
            _SUCCEEDED_XML,
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "MATCHED=2" in proc.stdout


def test_main_module_entry_point(tmp_path: Path) -> None:
    import runpy

    xml_file = tmp_path / "results.xml"
    xml_file.write_text(_SUCCEEDED_XML, encoding="utf-8")
    argv = [
        "obs_wait_build_status.py",
        "--package",
        "verilyze",
        "--repositories",
        "openSUSE_Tumbleweed",
        "--xml-file",
        str(xml_file),
    ]
    with patch.object(sys, "argv", argv):
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(str(_STATUS_MODULE), run_name="__main__")
    assert exc_info.value.code == 0
