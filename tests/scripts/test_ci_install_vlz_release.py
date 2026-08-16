# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for ci-install-vlz-release.sh and shared release install helpers."""

import hashlib
import os
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_INSTALL_SCRIPT = _ROOT / "scripts" / "ci-install-vlz-release.sh"
_COMMON_LIB = _ROOT / "scripts" / "lib" / "ci-install-vlz-release-common.sh"
_RESTORE_SCRIPT = _ROOT / "scripts" / "release-restore-download-layout.sh"
_LEGACY_LINUX_FLAT_ASSET_NAME = "vlz-linux-x86_64"
_LEGACY_LINUX_FLAT_ASSET_NAME_V031 = "vlz"


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


class TestCiInstallVlzRelease:
    def test_install_script_requires_download_dir(self) -> None:
        proc = subprocess.run(
            [str(_INSTALL_SCRIPT)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={k: v for k, v in os.environ.items() if k != "VLZ_RELEASE_DOWNLOAD_DIR"},
        )
        assert proc.returncode != 0
        assert "VLZ_RELEASE_DOWNLOAD_DIR is required" in proc.stderr

    def test_resolve_latest_release_tag_empty_fails(self, tmp_path: Path) -> None:
        fake_gh = tmp_path / "gh"
        fake_gh.write_text("#!/usr/bin/env bash\nprintf ''\n", encoding="utf-8")
        fake_gh.chmod(0o755)
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
if resolve_latest_release_tag "verilyze/verilyze"; then
  exit 9
fi
exit 0
"""
        proc = _run_bash(script, env={"PATH": f"{tmp_path}:{os.environ['PATH']}"})
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "no non-draft, non-prerelease" in proc.stderr

    def test_platform_archive_download_patterns_cover_macos_and_windows(self) -> None:
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
platform_archive_download_patterns 1.2.3 macos-aarch64
echo '---'
platform_archive_download_patterns 1.2.3 windows-x86_64
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        text = proc.stdout
        assert "vlz-1.2.3-macos-aarch64.tar.gz" in text
        assert "vlz-1.2.3-windows-x86_64.zip" in text
        assert "SHA256SUMS" in text

    def test_archive_install_script_requires_tag_and_platform(self) -> None:
        archive_script = _ROOT / "scripts" / "ci-install-vlz-release-archive.sh"
        proc = subprocess.run(
            [str(archive_script)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={
                k: v
                for k, v in os.environ.items()
                if k
                not in {
                    "VLZ_RELEASE_DOWNLOAD_DIR",
                    "VLZ_RELEASE_TAG",
                    "VLZ_RELEASE_PLATFORM",
                }
            },
        )
        assert proc.returncode != 0
        assert "VLZ_RELEASE_DOWNLOAD_DIR is required" in proc.stderr

    def test_linux_archive_download_patterns_include_versioned_archive(self) -> None:
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
linux_archive_download_patterns 1.2.3
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        patterns = [line for line in proc.stdout.splitlines() if line]
        assert "SHA256SUMS" in patterns
        assert "vlz-1.2.3-linux-x86_64.tar.gz" in patterns
        assert "vlz-1.2.3-linux-x86_64.tar.gz.sigstore.json" in patterns
        assert "vlz-1.2.3-linux-x86_64.tar.gz.intoto.jsonl" in patterns

    def test_legacy_linux_release_download_patterns_cover_raw_assets(self) -> None:
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
legacy_linux_release_download_patterns
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        patterns = [line for line in proc.stdout.splitlines() if line]
        assert f"{_LEGACY_LINUX_FLAT_ASSET_NAME}" in patterns
        assert f"{_LEGACY_LINUX_FLAT_ASSET_NAME_V031}" in patterns

    def test_restore_layout_from_legacy_platform_named_flat_linux_asset(
        self, tmp_path: Path
    ) -> None:
        download_dir = tmp_path / "release"
        download_dir.mkdir()
        payload = b"vlz-linux-x86_64-binary"
        download_dir.joinpath(_LEGACY_LINUX_FLAT_ASSET_NAME).write_bytes(payload)
        download_dir.joinpath(f"{_LEGACY_LINUX_FLAT_ASSET_NAME}.sigstore.json").write_text(
            "{}", encoding="utf-8"
        )
        download_dir.joinpath(f"{_LEGACY_LINUX_FLAT_ASSET_NAME}.intoto.jsonl").write_text(
            "{}", encoding="utf-8"
        )
        digest = hashlib.sha256(payload).hexdigest()
        download_dir.joinpath("SHA256SUMS").write_text(
            f"{digest}  {_LEGACY_LINUX_FLAT_ASSET_NAME}/vlz\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [str(_RESTORE_SCRIPT), str(download_dir)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        binary = download_dir / _LEGACY_LINUX_FLAT_ASSET_NAME / "vlz"
        assert binary.read_bytes() == payload
        assert (download_dir / f"{_LEGACY_LINUX_FLAT_ASSET_NAME}/vlz.sigstore.json").is_file()
        assert (download_dir / f"{_LEGACY_LINUX_FLAT_ASSET_NAME}/vlz.intoto.jsonl").is_file()

    def test_resolve_latest_release_tag_returns_tag(self, tmp_path: Path) -> None:
        fake_gh = tmp_path / "gh"
        fake_gh.write_text(
            "#!/usr/bin/env bash\nprintf 'v0.3.1'\n",
            encoding="utf-8",
        )
        fake_gh.chmod(0o755)
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
resolve_latest_release_tag "verilyze/verilyze"
"""
        proc = _run_bash(script, env={"PATH": f"{tmp_path}:{os.environ['PATH']}"})
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout.strip() == "v0.3.1"

    def test_tag_to_version_strips_v_prefix(self) -> None:
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
tag_to_version v1.2.3
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout.strip() == "1.2.3"

    def test_linux_archive_checksum_grep_matches_sha256sums(self, tmp_path: Path) -> None:
        root = tmp_path / "release"
        root.mkdir(parents=True)
        payload = b"archive-payload"
        rel_path = "vlz-1.2.3-linux-x86_64.tar.gz"
        root.joinpath(rel_path).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        root.joinpath("SHA256SUMS").write_text(
            f"{digest}  {rel_path}\n",
            encoding="utf-8",
        )
        script = f"""
set -euo pipefail
cd "{root}"
grep -F "{rel_path}" SHA256SUMS | sha256sum -c >&2
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout == ""
        assert f"{rel_path}: OK" in proc.stderr

    def test_verify_checksum_helper_keeps_stdout_clean(self, tmp_path: Path) -> None:
        """ci-install-vlz-release.sh prints only the binary path on stdout."""
        root = tmp_path / "release"
        rel_path = "vlz-1.2.3-linux-x86_64.tar.gz"
        root.mkdir(parents=True)
        payload = b"archive-payload"
        root.joinpath(rel_path).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        root.joinpath("SHA256SUMS").write_text(
            f"{digest}  {rel_path}\n",
            encoding="utf-8",
        )
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
root="{root}"
rel_path="{rel_path}"
(
  cd "${{root}}" || exit 1
  verify_sha256sums_entry "${{rel_path}}"
)
printf 'checksum-only'
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout == "checksum-only"
        assert f"{rel_path}: OK" in proc.stderr

    def test_verify_sha256sums_entry_when_sha256sum_is_bsd(self, tmp_path: Path) -> None:
        """macOS ships sha256sum without GNU -c; fall back to shasum."""
        root = tmp_path / "release"
        rel_path = "vlz-1.2.3-macos-aarch64.tar.gz"
        root.mkdir(parents=True)
        payload = b"macos-archive"
        root.joinpath(rel_path).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        root.joinpath("SHA256SUMS").write_text(
            f"{digest}  {rel_path}\n",
            encoding="utf-8",
        )
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        fake_sha = fake_bin / "sha256sum"
        fake_sha.write_text(
            "#!/bin/sh\necho 'usage: sha256sum [-bctwz] [files ...]' >&2\nexit 1\n",
            encoding="utf-8",
        )
        fake_sha.chmod(0o755)
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
cd "{root}"
verify_sha256sums_entry "{rel_path}"
"""
        proc = _run_bash(
            script,
            env={"PATH": f"{fake_bin}:{os.environ['PATH']}"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert f"{rel_path}: OK" in proc.stderr

    def test_verify_blob_attestation_uses_slsa_regex_first(
        self, tmp_path: Path
    ) -> None:
        fake_cosign = tmp_path / "cosign"
        fake_cosign.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != verify-blob-attestation ]]; then
  exit 9
fi
for arg in "$@"; do
  if [[ "$arg" == *slsa-framework* ]]; then
    exit 0
  fi
done
exit 1
""",
            encoding="utf-8",
        )
        fake_cosign.chmod(0o755)
        binary = tmp_path / "vlz"
        binary.write_bytes(b"bin")
        bundle = tmp_path / "vlz.intoto.jsonl"
        bundle.write_text("{}", encoding="utf-8")
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
verify_blob_attestation_with_builder_fallback \\
  "{binary}" \\
  "{bundle}" \\
  '^release\\.yml@' \\
  '^slsa-framework/'
"""
        proc = _run_bash(script, env={"PATH": f"{tmp_path}:{os.environ['PATH']}"})
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_verify_blob_attestation_falls_back_to_release_regex(
        self, tmp_path: Path
    ) -> None:
        fake_cosign = tmp_path / "cosign"
        fake_cosign.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != verify-blob-attestation ]]; then
  exit 9
fi
for arg in "$@"; do
  if [[ "$arg" == *slsa-framework* ]]; then
    exit 1
  fi
done
for arg in "$@"; do
  if [[ "$arg" == *workflows/release* ]]; then
    exit 0
  fi
done
exit 1
""",
            encoding="utf-8",
        )
        fake_cosign.chmod(0o755)
        binary = tmp_path / "vlz"
        binary.write_bytes(b"bin")
        bundle = tmp_path / "vlz.intoto.jsonl"
        bundle.write_text("{}", encoding="utf-8")
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
verify_blob_attestation_with_builder_fallback \\
  "{binary}" \\
  "{bundle}" \\
  '^https://github\\.com/verilyze/verilyze/\\.github/workflows/release\\.yml@' \\
  '^https://github\\.com/slsa-framework/'
"""
        proc = _run_bash(script, env={"PATH": f"{tmp_path}:{os.environ['PATH']}"})
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_verify_blob_attestation_fails_when_both_identities_reject(
        self, tmp_path: Path
    ) -> None:
        fake_cosign = tmp_path / "cosign"
        fake_cosign.write_text(
            "#!/usr/bin/env bash\nexit 1\n",
            encoding="utf-8",
        )
        fake_cosign.chmod(0o755)
        binary = tmp_path / "vlz"
        binary.write_bytes(b"bin")
        bundle = tmp_path / "vlz.intoto.jsonl"
        bundle.write_text("{}", encoding="utf-8")
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
if verify_blob_attestation_with_builder_fallback \\
  "{binary}" \\
  "{bundle}" \\
  '^release\\.yml@' \\
  '^slsa-framework/'; then
  exit 9
fi
exit 0
"""
        proc = _run_bash(script, env={"PATH": f"{tmp_path}:{os.environ['PATH']}"})
        assert proc.returncode == 0, proc.stderr + proc.stdout
