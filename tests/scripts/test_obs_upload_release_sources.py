# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS release source upload helper script."""

import os
import re
import subprocess
import tarfile
from pathlib import Path

from tests.scripts.workspace_helpers import (
    obs_changes_version_marker,
    obs_package_name,
    repo_root,
    workspace_semver,
)

_ROOT = repo_root()
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
    version = workspace_semver()
    package = obs_package_name()
    source_name = f"{package}-{version}.tar.xz"
    archive_prefix = f"{package}-{version}/"
    work_dir = tmp_path / "work"
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


def test_obs_upload_script_dry_run_vendor_archive_contains_offline_inputs(
    tmp_path: Path,
) -> None:
    work_dir = tmp_path / "work"
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


def test_obs_upload_script_uses_portable_osc_checkout_flags() -> None:
    """osc on Ubuntu/GitHub Actions lacks co --nosource; script must fallback."""
    text = _UPLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "osc_checkout_package" in text
    assert 'osc_cmd co -c "${project}" "${package}"' in text
    assert "co --meta" not in text


def test_obs_upload_script_avoids_metadata_only_checkout() -> None:
    """Metadata-only checkout breaks osc commit (_meta sha256 missing)."""
    text = _UPLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "_meta without sha256" in text


def test_obs_upload_script_renders_changes_from_changelog() -> None:
    text = _UPLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "render_obs_changes.py" in text
    assert "OBS_CHANGES_FILENAME" in text
    assert "OBS_LEGACY_CHANGES_FILENAME" in text


def test_obs_upload_script_removes_stale_source_archives() -> None:
    text = _UPLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "remove_stale_source_archives" in text
    assert '"${OBS_PACKAGE}"-*.tar.xz' in text


def test_obs_upload_script_uses_transient_osc_credentials() -> None:
    """Upload script delegates osc auth to lib/osc-cmd.sh (transient oscrc)."""
    text = _UPLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "setup_osc_auth" in text
    assert "lib/osc-cmd.sh" in text
    assert "pass = ${OBS_PASSWORD}" not in text
    assert "\npass = " not in text
    osc_lib = (_ROOT / "scripts" / "lib" / "osc-cmd.sh").read_text(encoding="utf-8")
    assert "[${OBS_API}]" in osc_lib
    assert "pass = ${obs_password}" in osc_lib
    assert "OSC_CONFIG" in osc_lib


def test_osc_cmd_uses_transient_config_file() -> None:
    """osc must read apiurl from OSC_CONFIG, not default ~/.oscrc."""
    text = (_ROOT / "scripts" / "lib" / "osc-cmd.sh").read_text(encoding="utf-8")
    assert 'config_args=(--config "${OSC_CONFIG}")' in text
    assert "osc --no-keyring" in text
    assert 'config_args=(-c "${OSC_CONFIG}")' not in text
