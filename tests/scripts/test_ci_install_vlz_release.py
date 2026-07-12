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
grep -F "vlz-linux-x86_64/vlz" SHA256SUMS | sha256sum -c
"""
        proc = _run_bash(script)
        assert proc.returncode == 0, proc.stderr + proc.stdout
