# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for versioned platform release archives and naming helpers."""

import os
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_NAMES_LIB = _ROOT / "scripts" / "lib" / "release-artifact-names.sh"
_BUILD = _ROOT / "scripts" / "release-build-platform-archive.sh"
_EXTRACT = _ROOT / "scripts" / "release-extract-platform-archive.sh"
_STAGE = _ROOT / "scripts" / "release-stage-github-upload.sh"
_LIST_UPLOAD = _ROOT / "scripts" / "release-list-github-upload-files.sh"
_VERIFY_UPLOAD = _ROOT / "scripts" / "release-verify-github-upload-files.sh"
_ROUNDTRIP = _ROOT / "scripts" / "release-verify-upload-roundtrip.sh"


def _run_bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


class TestReleaseArtifactNames:
    def test_archive_basenames_are_versioned_and_unique(self) -> None:
        script = f"""
set -euo pipefail
source "{_NAMES_LIB}"
release_archive_basename 1.2.3 linux-x86_64
release_archive_basename 1.2.3 macos-aarch64
release_archive_basename 1.2.3 windows-x86_64
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        lines = [line for line in proc.stdout.splitlines() if line]
        assert lines == [
            "vlz-1.2.3-linux-x86_64.tar.gz",
            "vlz-1.2.3-macos-aarch64.tar.gz",
            "vlz-1.2.3-windows-x86_64.zip",
        ]

    def test_exec_relpaths(self) -> None:
        script = f"""
set -euo pipefail
source "{_NAMES_LIB}"
release_exec_relpath linux-x86_64
release_exec_relpath windows-x86_64
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout.splitlines() == ["bin/vlz", "vlz.exe"]

    def test_is_slsa_archive_basename(self) -> None:
        script = f"""
set -euo pipefail
source "{_NAMES_LIB}"
release_is_slsa_archive_basename vlz-1.0.0-linux-x86_64.tar.gz && echo yes
release_is_slsa_archive_basename vlz_1.0.0_amd64.deb && echo no || true
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "yes" in proc.stdout
        assert "no" not in proc.stdout.splitlines()


class TestReleaseBuildPlatformArchive:
    def test_unix_archive_layout_and_executable_bit(self, tmp_path: Path) -> None:
        binary = tmp_path / "vlz"
        binary.write_bytes(b"unix-bin")
        binary.chmod(0o755)
        out = tmp_path / "out"
        out.mkdir()
        proc = subprocess.run(
            [
                str(_BUILD),
                "--platform",
                "linux-x86_64",
                "--version",
                "9.9.9",
                "--binary",
                str(binary),
                "--repo-root",
                str(_ROOT),
                "--output-dir",
                str(out),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        archive = out / "vlz-9.9.9-linux-x86_64.tar.gz"
        assert archive.is_file()
        with tarfile.open(archive, "r:gz") as tf:
            names = set(tf.getnames())
            assert "vlz-9.9.9-linux-x86_64/bin/vlz" in names
            assert "vlz-9.9.9-linux-x86_64/LICENSE" in names
            assert "vlz-9.9.9-linux-x86_64/INSTALL.md" in names
            assert "vlz-9.9.9-linux-x86_64/share/man/man1/vlz.1" in names
            assert "vlz-9.9.9-linux-x86_64/share/bash-completion/completions/vlz" in names
            # Allowlist: template / shellcheckrc must not ship.
            assert not any("verilyze.conf.5.in" in n for n in names)
            assert not any(".shellcheckrc" in n for n in names)
            member = tf.getmember("vlz-9.9.9-linux-x86_64/bin/vlz")
            assert member.mode & stat.S_IXUSR

    def test_windows_zip_layout(self, tmp_path: Path) -> None:
        binary = tmp_path / "vlz.exe"
        binary.write_bytes(b"win-bin")
        out = tmp_path / "out"
        out.mkdir()
        proc = subprocess.run(
            [
                str(_BUILD),
                "--platform",
                "windows-x86_64",
                "--version",
                "9.9.9",
                "--binary",
                str(binary),
                "--repo-root",
                str(_ROOT),
                "--output-dir",
                str(out),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        archive = out / "vlz-9.9.9-windows-x86_64.zip"
        assert archive.is_file()
        with zipfile.ZipFile(archive) as zf:
            names = set(zf.namelist())
            assert "vlz-9.9.9-windows-x86_64/vlz.exe" in names
            assert "vlz-9.9.9-windows-x86_64/verilyze.conf.example" in names
            assert not any("share/man" in n for n in names)
            assert not any("bash-completion" in n for n in names)

    def test_invalid_version_rejected(self, tmp_path: Path) -> None:
        binary = tmp_path / "vlz"
        binary.write_bytes(b"unix-bin")
        binary.chmod(0o755)
        out = tmp_path / "out"
        out.mkdir()
        proc = subprocess.run(
            [
                str(_BUILD),
                "--platform",
                "linux-x86_64",
                "--version",
                "not-a-version",
                "--binary",
                str(binary),
                "--repo-root",
                str(_ROOT),
                "--output-dir",
                str(out),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 2
        assert "SemVer" in proc.stderr

    def test_zip_slip_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../evil.txt", "bad")
        dest = tmp_path / "extract"
        proc = subprocess.run(
            [
                str(_EXTRACT),
                "--archive",
                str(archive),
                "--platform",
                "windows-x86_64",
                "--version",
                "1.0.0",
                "--dest",
                str(dest),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode != 0
        assert "unsafe" in (proc.stderr + proc.stdout).lower()

    def test_extract_returns_executable_path(self, tmp_path: Path) -> None:
        binary = tmp_path / "vlz"
        binary.write_bytes(b"unix-bin")
        binary.chmod(0o755)
        out = tmp_path / "out"
        out.mkdir()
        subprocess.run(
            [
                str(_BUILD),
                "--platform",
                "macos-aarch64",
                "--version",
                "1.0.0",
                "--binary",
                str(binary),
                "--repo-root",
                str(_ROOT),
                "--output-dir",
                str(out),
            ],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        dest = tmp_path / "extract"
        proc = subprocess.run(
            [
                str(_EXTRACT),
                "--archive",
                str(out / "vlz-1.0.0-macos-aarch64.tar.gz"),
                "--platform",
                "macos-aarch64",
                "--version",
                "1.0.0",
                "--dest",
                str(dest),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        exec_path = Path(proc.stdout.strip())
        assert exec_path.is_file()
        assert exec_path.name == "vlz"
        assert exec_path.stat().st_mode & stat.S_IXUSR


class TestReleaseStageGithubUpload:
    def test_stages_flat_unique_basenames(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "release-artifacts"
        version = "2.0.0"
        binary = tmp_path / "vlz"
        binary.write_bytes(b"bin")
        binary.chmod(0o755)
        exe = tmp_path / "vlz.exe"
        exe.write_bytes(b"exe")
        for platform, bin_path in (
            ("linux-x86_64", binary),
            ("macos-aarch64", binary),
            ("windows-x86_64", exe),
        ):
            out_dir = artifacts / f"vlz-{platform}"
            out_dir.mkdir(parents=True)
            subprocess.run(
                [
                    str(_BUILD),
                    "--platform",
                    platform,
                    "--version",
                    version,
                    "--binary",
                    str(bin_path),
                    "--repo-root",
                    str(_ROOT),
                    "--output-dir",
                    str(out_dir),
                ],
                cwd=_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
        deb_dir = artifacts / "deb-package"
        rpm_dir = artifacts / "rpm-package" / "x86_64"
        deb_dir.mkdir(parents=True)
        rpm_dir.mkdir(parents=True)
        (deb_dir / "vlz_2.0.0_amd64.deb").write_bytes(b"deb")
        (rpm_dir / "verilyze-2.0.0-1.x86_64.rpm").write_bytes(b"rpm")

        proc = subprocess.run(
            [str(_STAGE), str(artifacts), version],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        upload = artifacts / "github-upload"
        assert (upload / "vlz-2.0.0-linux-x86_64.tar.gz").is_file()
        assert (upload / "vlz-2.0.0-macos-aarch64.tar.gz").is_file()
        assert (upload / "vlz-2.0.0-windows-x86_64.zip").is_file()
        assert (upload / "vlz_2.0.0_amd64.deb").is_file()
        assert (upload / "verilyze-2.0.0-1.x86_64.rpm").is_file()


class TestReleaseGithubUploadFileList:
    def test_lists_and_verifies_signed_assets(self, tmp_path: Path) -> None:
        upload = tmp_path / "github-upload"
        upload.mkdir()
        names = ["vlz-1.0.0-linux-x86_64.tar.gz", "SHA256SUMS"]
        (upload / "ARTIFACTS.list").write_text(
            "\n".join(names) + "\n",
            encoding="utf-8",
        )
        for name in names:
            path = upload / name
            path.write_bytes(b"data")
            (upload / f"{name}.sigstore.json").write_bytes(b"sig")
            (upload / f"{name}.intoto.jsonl").write_bytes(b"att")

        list_proc = subprocess.run(
            [str(_LIST_UPLOAD), str(upload)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert list_proc.returncode == 0, list_proc.stderr + list_proc.stdout
        paths = [line for line in list_proc.stdout.splitlines() if line]
        assert len(paths) == 6
        verify_proc = subprocess.run(
            [str(_VERIFY_UPLOAD), "-"],
            cwd=_ROOT,
            input=list_proc.stdout,
            capture_output=True,
            text=True,
            check=False,
        )
        assert verify_proc.returncode == 0, verify_proc.stderr + verify_proc.stdout

    def test_verify_fails_on_missing_path(self, tmp_path: Path) -> None:
        paths_file = tmp_path / "paths.txt"
        paths_file.write_text("missing-file\n", encoding="utf-8")
        proc = subprocess.run(
            [str(_VERIFY_UPLOAD), str(paths_file)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1
        assert "missing" in proc.stderr.lower()


class TestReleaseUploadRoundtrip:
    def test_roundtrip_script_succeeds(self) -> None:
        proc = subprocess.run(
            [str(_ROUNDTRIP)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "round-trip" in (proc.stderr + proc.stdout).lower()
