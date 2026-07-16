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
_LINUX_FLAT_ASSET_NAME = "vlz-linux-x86_64"
_LEGACY_LINUX_FLAT_ASSET_NAME = "vlz"


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

    def test_linux_release_download_patterns_cover_platform_and_legacy(
        self,
    ) -> None:
        script = f"""
set -euo pipefail
source "{_COMMON_LIB}"
linux_release_download_patterns
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        patterns = [line for line in proc.stdout.splitlines() if line]
        assert "SHA256SUMS" in patterns
        assert f"{_LINUX_FLAT_ASSET_NAME}" in patterns
        assert f"{_LINUX_FLAT_ASSET_NAME}.sigstore.json" in patterns
        assert f"{_LINUX_FLAT_ASSET_NAME}.intoto.jsonl" in patterns
        assert f"{_LEGACY_LINUX_FLAT_ASSET_NAME}" in patterns
        assert f"{_LEGACY_LINUX_FLAT_ASSET_NAME}.sigstore.json" in patterns
        assert f"{_LEGACY_LINUX_FLAT_ASSET_NAME}.intoto.jsonl" in patterns

    def test_restore_layout_from_platform_named_flat_linux_asset(
        self, tmp_path: Path
    ) -> None:
        download_dir = tmp_path / "release"
        download_dir.mkdir()
        payload = b"vlz-linux-x86_64-binary"
        download_dir.joinpath(_LINUX_FLAT_ASSET_NAME).write_bytes(payload)
        download_dir.joinpath(f"{_LINUX_FLAT_ASSET_NAME}.sigstore.json").write_text(
            "{}", encoding="utf-8"
        )
        download_dir.joinpath(f"{_LINUX_FLAT_ASSET_NAME}.intoto.jsonl").write_text(
            "{}", encoding="utf-8"
        )
        digest = hashlib.sha256(payload).hexdigest()
        download_dir.joinpath("SHA256SUMS").write_text(
            f"{digest}  {_LINUX_FLAT_ASSET_NAME}/vlz\n",
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
        binary = download_dir / _LINUX_FLAT_ASSET_NAME / "vlz"
        assert binary.read_bytes() == payload
        assert (download_dir / f"{_LINUX_FLAT_ASSET_NAME}/vlz.sigstore.json").is_file()
        assert (download_dir / f"{_LINUX_FLAT_ASSET_NAME}/vlz.intoto.jsonl").is_file()

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

    def test_linux_binary_checksum_grep_matches_sha256sums(self, tmp_path: Path) -> None:
        root = tmp_path / "release"
        binary_dir = root / "vlz-linux-x86_64"
        binary_dir.mkdir(parents=True)
        payload = b"vlz-binary-payload"
        binary_dir.joinpath("vlz").write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        root.joinpath("SHA256SUMS").write_text(
            f"{digest}  vlz-linux-x86_64/vlz\n",
            encoding="utf-8",
        )
        script = f"""
set -euo pipefail
cd "{root}"
grep -F "vlz-linux-x86_64/vlz" SHA256SUMS | sha256sum -c >&2
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout == ""
        assert "vlz-linux-x86_64/vlz: OK" in proc.stderr

    def test_verify_checksum_helper_keeps_stdout_clean(self, tmp_path: Path) -> None:
        """ci-install-vlz-release.sh prints only the binary path on stdout."""
        root = tmp_path / "release"
        rel_path = "vlz-linux-x86_64/vlz"
        binary_dir = root / "vlz-linux-x86_64"
        binary_dir.mkdir(parents=True)
        payload = b"vlz-binary-payload"
        binary_dir.joinpath("vlz").write_bytes(payload)
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
  grep -F "${{rel_path}}" SHA256SUMS | sha256sum -c >&2
)
printf 'checksum-only'
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout == "checksum-only"
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
