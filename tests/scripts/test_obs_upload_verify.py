# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS upload source verification helpers."""

import subprocess
from pathlib import Path

import pytest

from scripts.obs_upload_verify import (
    extract_cargo_lock_from_vendor_archive,
    parse_obs_file_checksums,
    sha256_file,
    verify_obs_upload_checksums,
    verify_vendor_lockfile_matches_git_ref,
)
from tests.scripts.workspace_helpers import repo_root

_ROOT = repo_root()
_VENDOR_ARCHIVE = "vendor.tar.zst"


def _write_vendor_archive(path: Path, cargo_lock: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cargo_lock_path = path.parent / "Cargo.lock"
    cargo_lock_path.write_bytes(cargo_lock)
    subprocess.run(
        [
            "tar",
            "--zstd",
            "-cf",
            str(path),
            "-C",
            str(path.parent),
            "Cargo.lock",
        ],
        check=True,
    )


def test_extract_cargo_lock_from_vendor_archive(tmp_path: Path) -> None:
    expected = b"version = 4\n"
    archive = tmp_path / _VENDOR_ARCHIVE
    _write_vendor_archive(archive, expected)
    assert extract_cargo_lock_from_vendor_archive(archive) == expected


def test_verify_vendor_lockfile_matches_git_ref_accepts_matching_lockfile(
    tmp_path: Path,
) -> None:
    cargo_lock = (_ROOT / "Cargo.lock").read_bytes()
    archive = tmp_path / _VENDOR_ARCHIVE
    _write_vendor_archive(archive, cargo_lock)
    verify_vendor_lockfile_matches_git_ref(
        repo_root=_ROOT,
        git_ref="HEAD",
        vendor_archive=archive,
    )


def test_verify_vendor_lockfile_matches_git_ref_rejects_mismatch(
    tmp_path: Path,
) -> None:
    archive = tmp_path / _VENDOR_ARCHIVE
    _write_vendor_archive(archive, b"version = 4\n# stale\n")
    with pytest.raises(ValueError, match="Cargo.lock"):
        verify_vendor_lockfile_matches_git_ref(
            repo_root=_ROOT,
            git_ref="HEAD",
            vendor_archive=archive,
        )


def test_parse_obs_file_checksums_reads_sha256_attributes(tmp_path: Path) -> None:
    vendor_digest = "a" * 64
    spec_digest = "b" * 64
    meta = tmp_path / "_files"
    meta.write_text(
        (
            '<directory name="." rev="1" vrev="1">\n'
            f'  <file name="vendor.tar.zst" size="10" mtime="0" '
            f'sha256="{vendor_digest}"/>\n'
            f'  <file name="verilyze.spec" size="5" mtime="0" '
            f'sha256="{spec_digest}"/>\n'
            "</directory>\n"
        ),
        encoding="utf-8",
    )
    assert parse_obs_file_checksums(meta) == {
        "vendor.tar.zst": vendor_digest,
        "verilyze.spec": spec_digest,
    }


def test_parse_obs_file_checksums_reads_checksum_elements(tmp_path: Path) -> None:
    digest = "c" * 64
    meta = tmp_path / "_meta"
    meta.write_text(
        (
            "<package>\n"
            '  <file name="vendor.tar.zst">\n'
            f'    <checksum type="sha256">{digest}</checksum>\n'
            "  </file>\n"
            "</package>\n"
        ),
        encoding="utf-8",
    )
    assert parse_obs_file_checksums(meta) == {"vendor.tar.zst": digest}


def test_verify_obs_upload_checksums_matches_meta_and_files(tmp_path: Path) -> None:
    package_dir = tmp_path / "verilyze"
    package_dir.mkdir()
    vendor = package_dir / _VENDOR_ARCHIVE
    vendor.write_bytes(b"vendor bytes")
    vendor_digest = sha256_file(vendor)
    meta = package_dir / ".osc" / "_files"
    meta.parent.mkdir(parents=True)
    meta.write_text(
        (
            '<directory name="." rev="1" vrev="1">\n'
            f'  <file name="vendor.tar.zst" size="12" mtime="0" '
            f'sha256="{vendor_digest}"/>\n'
            "</directory>\n"
        ),
        encoding="utf-8",
    )
    verify_obs_upload_checksums(
        package_dir=package_dir,
        expected={_VENDOR_ARCHIVE: vendor_digest},
    )


def test_verify_obs_upload_checksums_rejects_meta_mismatch(tmp_path: Path) -> None:
    package_dir = tmp_path / "verilyze"
    package_dir.mkdir()
    vendor = package_dir / _VENDOR_ARCHIVE
    vendor.write_bytes(b"vendor bytes")
    meta = package_dir / ".osc" / "_files"
    meta.parent.mkdir(parents=True)
    meta.write_text(
        (
            '<directory name="." rev="1" vrev="1">\n'
            '  <file name="vendor.tar.zst" size="12" mtime="0" '
            'sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"/>\n'
            "</directory>\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_obs_upload_checksums(
            package_dir=package_dir,
            expected={
                _VENDOR_ARCHIVE: (
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
            },
        )


def test_dry_run_vendor_lockfile_matches_repo_head(tmp_path: Path) -> None:
    """Integration: upload script vendor archive matches HEAD Cargo.lock."""
    from tests.scripts.test_obs_upload_release_sources import _run_script
    from tests.scripts.workspace_helpers import workspace_semver

    work_dir = tmp_path / "work"
    proc = _run_script(
        [
            str(_ROOT / "scripts" / "obs-upload-release-sources.sh"),
            "--version",
            workspace_semver(),
            "--work-dir",
            str(work_dir),
            "--dry-run",
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout

    vendor_archive = work_dir / _VENDOR_ARCHIVE
    verify_vendor_lockfile_matches_git_ref(
        repo_root=_ROOT,
        git_ref="HEAD",
        vendor_archive=vendor_archive,
    )
