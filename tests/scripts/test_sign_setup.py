# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Behavioral tests for .cursor/sign-setup.sh exit codes."""

import os
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_SCRIPT = _ROOT / ".cursor" / "sign-setup.sh"


def _run(
    *,
    env: dict[str, str] | None = None,
    path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    for key in ("ssh_key", "ssh_key_pass", "git_signing_name", "git_signing_email"):
        merged.pop(key, None)
    if env:
        merged.update(env)
    if path is not None:
        merged["PATH"] = path
    return subprocess.run(
        ["bash", str(_SCRIPT)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


def _path_with_bash_only(tmp_path: Path) -> str:
    """Return a PATH that has bash but no ssh-keygen."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bash = Path("/bin/bash")
    if not bash.is_file():
        bash = Path("/usr/bin/bash")
    (bindir / "bash").symlink_to(bash)
    return str(bindir)


def test_sign_setup_skips_when_ssh_key_absent() -> None:
    result = _run()
    assert result.returncode == 0
    assert "ssh_key secret not present" in result.stdout


def test_sign_setup_fails_when_ssh_key_set_but_ssh_keygen_missing(
    tmp_path: Path,
) -> None:
    result = _run(
        env={"ssh_key": "not-a-real-key\n"},
        path=_path_with_bash_only(tmp_path),
    )
    assert result.returncode != 0
    assert "ssh-keygen not found" in result.stderr
