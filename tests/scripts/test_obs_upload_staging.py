# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS upload staging helpers."""

import os
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_STAGING_LIB = _ROOT / "scripts" / "lib" / "obs-upload-staging.sh"
_OSC_LIB = _ROOT / "scripts" / "lib" / "osc-cmd.sh"

_FAKE_OSC = """\
#!/usr/bin/env bash
set -eu
subcmd=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-keyring)
      shift
      ;;
    -A|--config)
      shift
      shift
      ;;
    *)
      subcmd="$1"
      shift
      break
      ;;
  esac
done
case "${subcmd}" in
  status)
    file="$1"
  if [[ "${file}" == "verilyze-0.2.4.tar.xz" ]]; then
      echo "?    verilyze-0.2.4.tar.xz"
      exit 0
    fi
    if [[ "${file}" == "verilyze.spec" ]]; then
      echo "    verilyze.spec"
      exit 0
    fi
    exit 1
    ;;
  add)
    echo "added $1"
    exit 0
    ;;
  commit)
    echo "nothing to do for package verilyze"
    exit 0
    ;;
  *)
    echo "unsupported: ${subcmd}" >&2
    exit 1
    ;;
esac
"""


def _run_staging_helper(
    tmp_path: Path,
    *,
    helper: str,
    args: str = "",
) -> subprocess.CompletedProcess[str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    osc_path = bindir / "osc"
    osc_path.write_text(_FAKE_OSC, encoding="utf-8")
    osc_path.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["OBS_API"] = "https://api.opensuse.org"
    script = f"""
set -euo pipefail
# shellcheck source=scripts/lib/osc-cmd.sh
source "{_OSC_LIB}"
# shellcheck source=scripts/lib/obs-upload-staging.sh
source "{_STAGING_LIB}"
{helper} {args}
"""
    return subprocess.run(
        ["bash", "-c", script],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_stage_file_adds_untracked_source_archive(tmp_path: Path) -> None:
    proc = _run_staging_helper(
        tmp_path,
        helper="osc_stage_file_for_commit",
        args='"verilyze-0.2.4.tar.xz"',
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "added verilyze-0.2.4.tar.xz" in output


def test_stage_file_skips_tracked_spec(tmp_path: Path) -> None:
    proc = _run_staging_helper(
        tmp_path,
        helper="osc_stage_file_for_commit",
        args='"verilyze.spec"',
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "added verilyze.spec" not in output


def test_commit_fails_when_osc_reports_nothing_to_do(tmp_path: Path) -> None:
    proc = _run_staging_helper(
        tmp_path,
        helper="osc_commit_package_upload",
        args='"Upload release 0.2.4 sources from GitHub Actions"',
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 1, output
    assert "nothing to do" in output
    assert "source archives may be missing" in output
