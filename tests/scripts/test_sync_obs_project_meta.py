# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS project _meta sync script."""

import os
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_SYNC_SCRIPT = _ROOT / "scripts" / "sync-obs-project-meta.sh"

_SAMPLE_META = """\
<?xml version="1.0" encoding="UTF-8"?>
<project name="home:example:proj">
  <title>example</title>
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Tumbleweed" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
</project>
"""

_SAMPLE_PACKAGE_META = """\
<package name="verilyze" project="home:example:proj">
  <title>verilyze</title>
  <build>
    <disable repository="Fedora_43"/>
  </build>
</package>
"""

_FAKE_OSC_SCRIPT = """\
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-keyring) shift ;;
    --config) shift 2 ;;
    -A) shift 2 ;;
    api)
      shift
      if [[ "${1:-}" == "-X" ]]; then
        target=""
        for arg in "$@"; do
          if [[ "${arg}" == /source/* ]]; then
            target="${arg}"
            break
          fi
        done
        if [[ "${target}" == *"/verilyze/_meta" ]]; then
          echo "package-meta-updated" >"${OSC_FAKE_STATE_DIR}/package-meta-updated"
        else
          echo "project-meta-updated" >"${OSC_FAKE_STATE_DIR}/project-meta-updated"
        fi
        exit 0
      fi
      target=""
      for arg in "$@"; do
        if [[ "${arg}" == /source/* ]]; then
          target="${arg}"
          break
        fi
      done
      if [[ "${target}" == *"/verilyze/_meta" ]]; then
        cat "${OSC_FAKE_STATE_DIR}/live-package-meta.xml"
        exit 0
      fi
      cat "${OSC_FAKE_STATE_DIR}/live-project-meta.xml"
      exit 0
      ;;
    *) shift ;;
  esac
done
exit 1
"""


def _write_fake_osc(tmp_path: Path) -> Path:
    state_dir = tmp_path / "osc-state"
    state_dir.mkdir()
    (state_dir / "live-project-meta.xml").write_text(
        '<project name="home:example:proj"><title>other</title></project>',
        encoding="utf-8",
    )
    (state_dir / "live-package-meta.xml").write_text(
        '<package name="verilyze"><title>stale</title></package>',
        encoding="utf-8",
    )
    fake_osc = tmp_path / "osc"
    fake_osc.write_text(_FAKE_OSC_SCRIPT, encoding="utf-8")
    fake_osc.chmod(0o755)
    return fake_osc


def _run_script(
    argv: list[str],
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for key in ("OBS_USER", "OBS_PASSWORD", "OSC_USERNAME", "OSC_PASSWORD"):
        env.pop(key, None)
    if extra_env is not None:
        env.update(extra_env)
    return subprocess.run(
        argv,
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_sync_script_dry_run_push_prints_paths(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    meta_file = tmp_path / "project" / "_meta"
    meta_file.parent.mkdir(parents=True)
    meta_file.write_text(_SAMPLE_META, encoding="utf-8")
    env_file.write_text(
        "\n".join(
            [
                "OBS_PROJECT=home:example:proj",
                "OBS_PACKAGE=verilyze",
                "",
            ]
        ),
        encoding="utf-8",
    )

    proc = _run_script(
        [
            str(_SYNC_SCRIPT),
            "--config",
            str(env_file),
            "--project-meta",
            str(meta_file),
            "--push",
            "--dry-run",
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "dry-run" in output.lower()
    assert "home:example:proj" in output
    assert str(meta_file) in output or "project/_meta" in output


def test_sync_script_push_requires_credentials(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    meta_file = tmp_path / "project" / "_meta"
    meta_file.parent.mkdir(parents=True)
    meta_file.write_text(_SAMPLE_META, encoding="utf-8")
    env_file.write_text(
        "OBS_PROJECT=home:example:proj\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )
    _write_fake_osc(tmp_path)

    proc = _run_script(
        [
            str(_SYNC_SCRIPT),
            "--config",
            str(env_file),
            "--project-meta",
            str(meta_file),
            "--push",
        ],
        extra_env={"PATH": f"{tmp_path}:{os.environ.get('PATH', '')}"},
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "OBS_USER" in output or "OSC_" in output


def test_sync_script_push_requires_project_meta_file(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "OBS_PROJECT=home:example:proj\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )

    proc = _run_script(
        [
            str(_SYNC_SCRIPT),
            "--config",
            str(env_file),
            "--project-meta",
            str(tmp_path / "missing" / "_meta"),
            "--push",
            "--dry-run",
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "_meta" in output


def test_sync_script_check_exits_nonzero_on_drift(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    meta_file = tmp_path / "project" / "_meta"
    meta_file.parent.mkdir(parents=True)
    meta_file.write_text(_SAMPLE_META, encoding="utf-8")
    env_file.write_text(
        "OBS_PROJECT=home:example:proj\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )

    _write_fake_osc(tmp_path)

    proc = _run_script(
        [
            str(_SYNC_SCRIPT),
            "--config",
            str(env_file),
            "--project-meta",
            str(meta_file),
            "--check",
        ],
        extra_env={
            "OBS_USER": "tester",
            "OBS_PASSWORD": "secret",
            "OSC_FAKE_STATE_DIR": str(tmp_path / "osc-state"),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 1, output
    assert "drift" in output.lower() or "diff" in output.lower()


def test_sync_script_push_updates_project_and_package_meta(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    project_meta = tmp_path / "project" / "_meta"
    package_meta = tmp_path / "rpm" / "_meta"
    project_meta.parent.mkdir(parents=True)
    package_meta.parent.mkdir(parents=True)
    project_meta.write_text(_SAMPLE_META, encoding="utf-8")
    package_meta.write_text(_SAMPLE_PACKAGE_META, encoding="utf-8")
    env_file.write_text(
        "OBS_PROJECT=home:example:proj\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )
    state_dir = tmp_path / "osc-state"
    state_dir.mkdir()
    (state_dir / "live-project-meta.xml").write_text(_SAMPLE_META, encoding="utf-8")
    (state_dir / "live-package-meta.xml").write_text(
        _SAMPLE_PACKAGE_META,
        encoding="utf-8",
    )
    fake_osc = tmp_path / "osc"
    fake_osc.write_text(_FAKE_OSC_SCRIPT, encoding="utf-8")
    fake_osc.chmod(0o755)

    proc = _run_script(
        [
            str(_SYNC_SCRIPT),
            "--config",
            str(env_file),
            "--project-meta",
            str(project_meta),
            "--package-meta",
            str(package_meta),
            "--push",
        ],
        extra_env={
            "OBS_USER": "tester",
            "OBS_PASSWORD": "secret",
            "OSC_FAKE_STATE_DIR": str(state_dir),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "project meta pushed" in output
    assert "package meta pushed" in output
    assert (state_dir / "project-meta-updated").is_file()
    assert (state_dir / "package-meta-updated").is_file()


def test_sync_script_check_fails_when_package_meta_drifts(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    project_meta = tmp_path / "project" / "_meta"
    package_meta = tmp_path / "rpm" / "_meta"
    project_meta.parent.mkdir(parents=True)
    package_meta.parent.mkdir(parents=True)
    project_meta.write_text(_SAMPLE_META, encoding="utf-8")
    package_meta.write_text(_SAMPLE_PACKAGE_META, encoding="utf-8")
    env_file.write_text(
        "OBS_PROJECT=home:example:proj\nOBS_PACKAGE=verilyze\n",
        encoding="utf-8",
    )
    state_dir = tmp_path / "osc-state"
    state_dir.mkdir()
    (state_dir / "live-project-meta.xml").write_text(_SAMPLE_META, encoding="utf-8")
    (state_dir / "live-package-meta.xml").write_text(
        '<package name="verilyze"><title>stale</title></package>',
        encoding="utf-8",
    )
    fake_osc = tmp_path / "osc"
    fake_osc.write_text(_FAKE_OSC_SCRIPT, encoding="utf-8")
    fake_osc.chmod(0o755)

    proc = _run_script(
        [
            str(_SYNC_SCRIPT),
            "--config",
            str(env_file),
            "--project-meta",
            str(project_meta),
            "--package-meta",
            str(package_meta),
            "--check",
        ],
        extra_env={
            "OBS_USER": "tester",
            "OBS_PASSWORD": "secret",
            "OSC_FAKE_STATE_DIR": str(state_dir),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 1, output
    assert "package _meta drift" in output.lower()
