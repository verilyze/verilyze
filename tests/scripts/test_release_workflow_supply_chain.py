# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for release signing and provenance workflow coverage."""

import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_RESTORE_SCRIPT = _ROOT / "scripts" / "release-restore-download-layout.sh"


def test_release_backfill_workflow_removed() -> None:
    backfill = _ROOT / ".github" / "workflows" / "release-backfill-metadata.yml"
    assert not backfill.exists()


def test_release_restore_download_layout_uses_rpm_x86_64_path(tmp_path: Path) -> None:
    download_dir = tmp_path / "draft-verify"
    download_dir.mkdir()
    (download_dir / "vlz").write_bytes(b"vlz-binary")
    (download_dir / "vlz_0.1.0_amd64.deb").write_bytes(b"deb-pkg")
    (download_dir / "vlz-0.1.0-1.x86_64.rpm").write_bytes(b"rpm-pkg")

    proc = subprocess.run(
        [str(_RESTORE_SCRIPT), str(download_dir)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (download_dir / "rpm-package" / "x86_64" / "vlz-0.1.0-1.x86_64.rpm").is_file()


def test_release_read_workspace_version_script_matches_cargo_toml() -> None:
    script = _ROOT / "scripts" / "release-read-workspace-version.sh"
    cargo = _ROOT / "Cargo.toml"
    assert script.is_file()
    proc = subprocess.run(
        [str(script), str(cargo)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    version_line = next(
        line for line in cargo.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("version = ")
    )
    cargo_version = version_line.split("=", 1)[1].strip().strip('"')
    assert proc.stdout.strip() == cargo_version
