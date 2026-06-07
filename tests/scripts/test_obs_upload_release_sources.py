# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS release source upload helper script."""

import os
import re
import subprocess
import tarfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_UPLOAD_SCRIPT = _ROOT / "scripts" / "obs-upload-release-sources.sh"
_OBS_SPEC_TEMPLATE = _ROOT / "packaging" / "obs" / "rpm" / "verilyze.spec"
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


def test_obs_upload_script_dry_run_builds_expected_artifacts(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    proc = _run_script(
        [
            str(_UPLOAD_SCRIPT),
            "--version",
            "0.2.1",
            "--work-dir",
            str(work_dir),
            "--dry-run",
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "verilyze-0.2.1.tar.xz" in output
    assert _VENDOR_ARCHIVE in output
    assert "verilyze.spec" in output
    assert "dry-run" in output.lower()

    source_archive = work_dir / "verilyze-0.2.1.tar.xz"
    vendor_archive = work_dir / _VENDOR_ARCHIVE
    spec_file = work_dir / "verilyze.spec"
    assert source_archive.is_file()
    assert vendor_archive.is_file()
    assert spec_file.is_file()
    assert re.search(r"^Version:\s+0\.2\.1$", spec_file.read_text(encoding="utf-8"), re.M)

    with tarfile.open(source_archive, "r:xz") as tarball:
        names = tarball.getnames()
    assert any(name.startswith("verilyze-0.2.1/") for name in names)


def test_obs_upload_script_dry_run_vendor_archive_contains_offline_inputs(
    tmp_path: Path,
) -> None:
    work_dir = tmp_path / "work"
    proc = _run_script(
        [
            str(_UPLOAD_SCRIPT),
            "--version",
            "0.2.1",
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


def test_obs_upload_script_uses_portable_osc_checkout_flags() -> None:
    """osc on Ubuntu/GitHub Actions lacks co --nosource; script must fallback."""
    text = _UPLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "osc_checkout_package" in text
    assert "--meta" in text or 'co -M' in text
