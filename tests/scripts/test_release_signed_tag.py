# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/release-signed-tag.sh."""

import os
import stat
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root
from tests.scripts.workspace_helpers import workspace_semver

_ROOT = repo_root()
_SCRIPT = _ROOT / "scripts" / "release-signed-tag.sh"
_CARGO = _ROOT / "Cargo.toml"


def _tag() -> str:
    return f"v{workspace_semver(_CARGO)}"


def _run(
    *args: str,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [str(_SCRIPT), *args],
        cwd=cwd or _ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


def _install_fakes(
    tmp_path: Path,
    *,
    gh_view: str,
    gh_view_code: int = 0,
    gh_view_stderr: str = "",
    git_remote_delete_code: int = 0,
    git_remote_delete_stderr: str = "",
) -> tuple[dict[str, str], Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "cmd.log"
    gh = bindir / "gh"
    git = bindir / "git"
    gh.write_text(
        "#!/bin/sh\n"
        f'echo "gh $*" >> "{log}"\n'
        'if [ "$1" = release ] && [ "$2" = view ]; then\n'
        f'  printf "%s" "{gh_view_stderr}" >&2\n'
        f'  printf "%s\\n" "{gh_view}"\n'
        f"  exit {gh_view_code}\n"
        "fi\n"
        'if [ "$1" = release ] && [ "$2" = delete ]; then\n'
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    git.write_text(
        "#!/bin/sh\n"
        f'echo "git $*" >> "{log}"\n'
        'case " $* " in\n'
        '  *" :refs/tags/"*)\n'
        f'    printf "%s" "{git_remote_delete_stderr}" >&2\n'
        f"    exit {git_remote_delete_code}\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    git.chmod(git.stat().st_mode | stat.S_IEXEC)
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "GIT_DIR": str(tmp_path / "no-git"),
    }
    return env, log


def test_usage_without_args() -> None:
    proc = _run()
    assert proc.returncode == 2
    assert "usage:" in proc.stderr


def test_rejects_tag_without_v_prefix() -> None:
    proc = _run("push", "1.2.3", "--dry-run")
    assert proc.returncode == 2
    assert "usage:" in proc.stderr or "must start with v" in proc.stderr


def test_dry_run_push_prints_tag_and_push(tmp_path: Path) -> None:
    tag = _tag()
    env, _log = _install_fakes(tmp_path, gh_view="", gh_view_code=1, gh_view_stderr="release not found")
    proc = _run("push", tag, "--dry-run", env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert any("git tag -s" in ln and tag in ln for ln in lines)
    assert f"git push origin {tag}" in lines


def test_dry_run_move_when_missing_skips_gh_delete(tmp_path: Path) -> None:
    tag = _tag()
    env, _log = _install_fakes(tmp_path, gh_view="", gh_view_code=1, gh_view_stderr="release not found")
    proc = _run("move", tag, "--dry-run", env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    text = proc.stdout
    assert "gh release delete" not in text
    assert f"git tag -d {tag}" in text
    assert f"git push origin :refs/tags/{tag}" in text
    assert f"git push origin {tag}" in text


def test_dry_run_move_when_draft_prints_gh_delete(tmp_path: Path) -> None:
    tag = _tag()
    env, _log = _install_fakes(tmp_path, gh_view="true")
    proc = _run("move", tag, "--dry-run", env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "gh release delete" in proc.stdout


def test_dry_run_move_aborts_when_published(tmp_path: Path) -> None:
    tag = _tag()
    env, log = _install_fakes(tmp_path, gh_view="false")
    proc = _run("move", tag, "--dry-run", env=env)
    assert proc.returncode != 0
    assert "not a draft" in (proc.stderr + proc.stdout).lower()
    assert "gh release delete" not in proc.stdout
    assert not log.exists() or "git " not in log.read_text(encoding="utf-8")


def test_push_aborts_when_published(tmp_path: Path) -> None:
    tag = _tag()
    env, log = _install_fakes(tmp_path, gh_view="false")
    proc = _run("push", tag, env=env)
    assert proc.returncode != 0
    assert "not a draft" in (proc.stderr + proc.stdout).lower()
    assert not log.exists() or "git " not in log.read_text(encoding="utf-8")


def test_move_aborts_when_release_is_not_draft(tmp_path: Path) -> None:
    tag = _tag()
    env, log = _install_fakes(tmp_path, gh_view="false")
    proc = _run("move", tag, env=env)
    assert proc.returncode != 0
    assert "draft" in (proc.stderr + proc.stdout).lower()
    assert not log.exists() or "git " not in log.read_text(encoding="utf-8")


def test_move_aborts_when_release_view_fails(tmp_path: Path) -> None:
    tag = _tag()
    env, log = _install_fakes(
        tmp_path,
        gh_view="",
        gh_view_code=1,
        gh_view_stderr="API rate limit exceeded",
    )
    proc = _run("move", tag, env=env)
    assert proc.returncode != 0
    assert "could not determine" in (proc.stderr + proc.stdout).lower()
    assert not log.exists() or "git " not in log.read_text(encoding="utf-8")


def test_move_continues_when_remote_tag_already_gone(tmp_path: Path) -> None:
    tag = _tag()
    env, log = _install_fakes(
        tmp_path,
        gh_view="",
        gh_view_code=1,
        gh_view_stderr="HTTP 404: Not Found (release not found)",
        git_remote_delete_code=1,
        git_remote_delete_stderr="error: unable to delete 'refs/tags/x': remote ref does not exist",
    )
    proc = _run("move", tag, env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    logged = log.read_text(encoding="utf-8")
    assert "git tag -s" in logged
    assert f"git push origin {tag}" in logged


def test_makefile_release_tag_push_requires_tag() -> None:
    proc = subprocess.run(
        ["make", "-C", str(_ROOT), "release-tag-push"],
        capture_output=True,
        text=True,
        check=False,
        env={k: v for k, v in os.environ.items() if k != "TAG"},
    )
    assert proc.returncode != 0
    assert "TAG is required" in (proc.stderr + proc.stdout)
