# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for .cursor/skills/verilyze-ship-pr/scripts/ship-pr.sh."""

import os
import stat
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_SCRIPT = (
    _ROOT / ".cursor" / "skills" / "verilyze-ship-pr" / "scripts" / "ship-pr.sh"
)


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


def _init_repo(tmp_path: Path, *, branch: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "ship-pr@test.example"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Ship PR Test"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    (repo / "README.md").write_text("test\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "README.md"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    if branch != "main":
        subprocess.run(
            ["git", "checkout", "-b", branch],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
    return repo


def _install_fakes(
    tmp_path: Path,
    *,
    branch: str = "feat/test",
    pr_state: str | None = None,
    pr_view_fails: bool = False,
) -> tuple[dict[str, str], Path, Path]:
    repo = _init_repo(tmp_path, branch=branch)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "cmd.log"

    pr_json = ""
    pr_exit = 0
    if pr_view_fails:
        pr_exit = 1
    elif pr_state is not None:
        pr_json = pr_state

    gh = bindir / "gh"
    gh.write_text(
        "#!/bin/sh\n"
        f'echo "gh $*" >> "{log}"\n'
        'if [ "$1" = pr ] && [ "$2" = view ]; then\n'
        f'  if [ {pr_exit} -ne 0 ]; then exit {pr_exit}; fi\n'
        f'  if [ -n "{pr_json}" ]; then printf "%s\\n" "{pr_json}"; fi\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = pr ] && [ "$2" = merge ]; then\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = pr ] && [ "$2" = create ]; then\n'
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    git = bindir / "git"
    git.write_text(
        "#!/bin/sh\n"
        f'echo "git $*" >> "{log}"\n'
        'case " $* " in\n'
        '  *" rev-parse --is-inside-work-tree "*)\n'
        "    exit 0\n"
        "    ;;\n"
        '  *" rev-parse --show-toplevel "*)\n'
        f'    printf "%s\\n" "{repo}"\n'
        "    exit 0\n"
        "    ;;\n"
        '  *" branch --show-current "*)\n'
        f'    printf "%s\\n" "{branch}"\n'
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    git.chmod(git.stat().st_mode | stat.S_IEXEC)
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "VLZ_SHIP_PR_MERGE_POLL_MAX": "1",
        "VLZ_SHIP_PR_MERGE_POLL_SLEEP": "0",
    }
    return env, log, repo


def test_usage_without_args() -> None:
    proc = _run()
    assert proc.returncode == 2
    assert "usage:" in proc.stderr


def test_create_pr_requires_title_and_body_file(tmp_path: Path) -> None:
    env, _log, repo = _install_fakes(tmp_path)
    proc = _run("create-pr", env=env, cwd=repo)
    assert proc.returncode == 2
    assert "usage:" in proc.stderr


def test_create_pr_rejects_missing_body_file(tmp_path: Path) -> None:
    env, _log, repo = _install_fakes(tmp_path)
    proc = _run(
        "create-pr",
        "--title",
        "feat: test",
        "--body-file",
        str(tmp_path / "missing.md"),
        env=env,
        cwd=repo,
    )
    assert proc.returncode == 1
    assert "body file not found" in proc.stderr


def test_push_rejects_main_branch(tmp_path: Path) -> None:
    env, log, repo = _install_fakes(tmp_path, branch="main")
    proc = _run("push", env=env, cwd=repo)
    assert proc.returncode == 1
    assert "refusing remote write on main" in proc.stderr
    assert not log.exists() or "git push" not in log.read_text(encoding="utf-8")


def test_merge_requires_open_pr(tmp_path: Path) -> None:
    env, log, repo = _install_fakes(tmp_path, pr_view_fails=True)
    proc = _run("merge", env=env, cwd=repo)
    assert proc.returncode == 1
    assert "no open PR" in proc.stderr
    assert not log.exists() or "gh pr merge" not in log.read_text(encoding="utf-8")


def test_merge_aborts_when_pr_already_merged(tmp_path: Path) -> None:
    env, log, repo = _install_fakes(tmp_path, pr_state="MERGED")
    proc = _run("merge", env=env, cwd=repo)
    assert proc.returncode == 1
    assert "already merged" in proc.stderr
    assert not log.exists() or "gh pr merge" not in log.read_text(encoding="utf-8")


def test_merge_invokes_gh_and_times_out_when_still_open(tmp_path: Path) -> None:
    env, log, repo = _install_fakes(tmp_path, pr_state="OPEN")
    proc = _run("merge", env=env, cwd=repo)
    assert proc.returncode == 1
    assert "expected MERGED" in proc.stderr
    logged = log.read_text(encoding="utf-8")
    assert "gh pr merge --merge --admin" in logged


def test_push_from_subdirectory_uses_repo_root(tmp_path: Path) -> None:
    env, log, repo = _install_fakes(tmp_path)
    subdir = repo / "crates" / "foo"
    subdir.mkdir(parents=True)
    proc = _run("push", env=env, cwd=subdir)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "git push -u origin HEAD" in log.read_text(encoding="utf-8")
