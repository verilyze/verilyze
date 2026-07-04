# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS release source upload helper script."""

import os
import re
import subprocess
import tarfile
from pathlib import Path

from tests.scripts.repo_root import repo_root
from tests.scripts.workspace_helpers import (
    obs_changes_version_marker,
    obs_package_name,
    workspace_semver,
)

_ROOT = repo_root()
_UPLOAD_SCRIPT = _ROOT / "scripts" / "obs-upload-release-sources.sh"
_VENDOR_ARCHIVE = "vendor.tar.zst"


def _run_script(
    argv: list[str],
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for key in ("OBS_USER", "OBS_PASSWORD"):
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


def test_obs_upload_script_dry_run_builds_expected_artifacts(
    obs_dry_run_work_dir: Path,
) -> None:
    version = workspace_semver()
    package = obs_package_name()
    source_name = f"{package}-{version}.tar.xz"
    archive_prefix = f"{package}-{version}/"
    work_dir = obs_dry_run_work_dir
    proc = _run_script(
        [
            str(_UPLOAD_SCRIPT),
            "--version",
            version,
            "--work-dir",
            str(work_dir),
            "--dry-run",
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert source_name in output
    assert _VENDOR_ARCHIVE in output
    assert "verilyze.spec" in output
    assert "verilyze.changes" in output
    assert "changes_sha256=" in output
    assert "dry-run" in output.lower()

    source_archive = work_dir / source_name
    vendor_archive = work_dir / _VENDOR_ARCHIVE
    spec_file = work_dir / "verilyze.spec"
    changes_file = work_dir / "verilyze.changes"
    assert source_archive.is_file()
    assert vendor_archive.is_file()
    assert spec_file.is_file()
    assert changes_file.is_file()
    spec_text = spec_file.read_text(encoding="utf-8")
    assert re.search(rf"^Version:\s+{re.escape(version)}$", spec_text, re.M)
    assert obs_changes_version_marker(version) in changes_file.read_text(
        encoding="utf-8"
    )

    with tarfile.open(source_archive, "r:xz") as tarball:
        names = tarball.getnames()
    assert any(name.startswith(archive_prefix) for name in names)
    assert not (work_dir / "vendor-build").exists()


def test_obs_upload_script_dry_run_vendor_archive_contains_offline_inputs(
    obs_dry_run_work_dir: Path,
) -> None:
    work_dir = obs_dry_run_work_dir
    proc = _run_script(
        [
            str(_UPLOAD_SCRIPT),
            "--version",
            workspace_semver(),
            "--work-dir",
            str(work_dir),
            "--dry-run",
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout

    vendor_archive = work_dir / _VENDOR_ARCHIVE
    listing = subprocess.run(
        ["tar", "--zstd", "-tf", str(vendor_archive)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert listing.returncode == 0, listing.stderr
    names = set(listing.stdout.splitlines())
    assert any(name.startswith("vendor/") for name in names)
    assert ".cargo/config.toml" in names
    assert "Cargo.lock" in names


def test_obs_upload_script_requires_version() -> None:
    proc = _run_script([str(_UPLOAD_SCRIPT), "--dry-run"])
    assert proc.returncode == 1
    assert "--version" in (proc.stderr + proc.stdout)


def test_obs_upload_script_empty_work_dir_uses_mktemp_not_shallow_rm() -> None:
    proc = _run_script(
        [
            str(_UPLOAD_SCRIPT),
            "--version",
            workspace_semver(),
            "--work-dir",
            "",
            "--dry-run",
        ]
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "refusing to remove shallow" not in output.lower()
    assert "/vendor-build" not in output
    assert "dry-run" in output.lower()


def test_obs_upload_script_dry_run_excludes_rpmlintrc_artifact(
    obs_dry_run_work_dir: Path,
) -> None:
    work_dir = obs_dry_run_work_dir
    proc = _run_script(
        [
            str(_UPLOAD_SCRIPT),
            "--version",
            workspace_semver(),
            "--work-dir",
            str(work_dir),
            "--dry-run",
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert not (work_dir / "verilyze-rpmlintrc").exists()
    assert "rpmlintrc_sha256=" not in proc.stdout + proc.stderr
