# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/ai-learnings-gh-post.sh."""

import os
import stat
import subprocess
import textwrap
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_SCRIPT = _ROOT / "scripts" / "ai-learnings-gh-post.sh"
_LABEL = "ai-learnings"
_TYPE = "Learning"


def _run(
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [str(_SCRIPT), *args],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


def _install_fakes(
    tmp_path: Path,
    *,
    view_label: bool = True,
    view_type: bool = True,
    sticky_miss: bool = False,
) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "cmd.log"
    state = tmp_path / "state"
    state.write_text(
        f"label={'1' if view_label else '0'}\n"
        f"type={'1' if view_type else '0'}\n"
        f"sticky={'1' if sticky_miss else '0'}\n",
        encoding="utf-8",
    )
    gitleaks = bindir / "gitleaks"
    gitleaks.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gh = bindir / "gh"
    gh.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            echo "gh $*" >> "{log}"
            case "$1" in
              issue)
                case "$2" in
                  create)
                    if echo "$*" | grep -q -- '--jq'; then
                      echo "99 https://github.com/verilyze/verilyze/issues/99"
                    else
                      echo "https://github.com/verilyze/verilyze/issues/99"
                    fi
                    exit 0
                    ;;
                  view)
                    mode=""
                    for arg in "$@"; do
                      case "$arg" in
                        --jq) mode="jq" ;;
                      esac
                    done
                    label=$(grep '^label=' "{state}" | cut -d= -f2)
                    typ=$(grep '^type=' "{state}" | cut -d= -f2)
                    if [ "$mode" = "jq" ]; then
                      case "$*" in
                        *labels*)
                          if [ "$label" = "1" ]; then echo true; else echo false; fi
                          ;;
                        *issueType*)
                          if [ "$typ" = "1" ]; then echo true; else echo false; fi
                          ;;
                      esac
                      exit 0
                    fi
                    exit 0
                    ;;
                  edit)
                    sticky=$(grep '^sticky=' "{state}" | cut -d= -f2)
                    if [ "$sticky" != "1" ]; then
                      if echo "$*" | grep -q -- '--add-label'; then
                        sed -i 's/^label=0/label=1/' "{state}"
                      fi
                      if echo "$*" | grep -q -- '--type'; then
                        sed -i 's/^type=0/type=1/' "{state}"
                      fi
                    fi
                    exit 0
                    ;;
                esac
                ;;
            esac
            exit 1
            """
        ),
        encoding="utf-8",
    )
    gitleaks.chmod(gitleaks.stat().st_mode | stat.S_IEXEC)
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    return {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "AI_LEARNINGS_TEST_LOG": str(log),
        "AI_LEARNINGS_TEST_STATE": str(state),
    }


def _log_text(env: dict[str, str]) -> str:
    return Path(env["AI_LEARNINGS_TEST_LOG"]).read_text(encoding="utf-8")


def test_issue_create_rejects_custom_label(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Fingerprint: test:x\n", encoding="utf-8")
    env = _install_fakes(tmp_path)
    proc = _run(
        "issue-create",
        "--title",
        "ci-gap: test -- example",
        "--label",
        "bug",
        "--body-file",
        str(body),
        env=env,
    )
    assert proc.returncode == 2
    assert "--label is not supported" in proc.stderr


def test_issue_create_passes_label_and_type(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Fingerprint: test:x\n", encoding="utf-8")
    env = _install_fakes(tmp_path)
    proc = _run(
        "issue-create",
        "--title",
        "ci-gap: test -- example",
        "--body-file",
        str(body),
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    log = _log_text(env)
    assert f"--label {_LABEL}" in log
    assert f"--type {_TYPE}" in log
    assert "https://github.com/verilyze/verilyze/issues/99" in proc.stdout


def test_issue_create_repairs_missing_metadata(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Fingerprint: test:x\n", encoding="utf-8")
    env = _install_fakes(tmp_path, view_label=False, view_type=False, sticky_miss=False)
    proc = _run(
        "issue-create",
        "--title",
        "agent: test -- example",
        "--body-file",
        str(body),
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    log = _log_text(env)
    assert "issue edit" in log
    assert f"--add-label {_LABEL}" in log
    assert f"--type {_TYPE}" in log


def test_issue_create_fails_when_repair_insufficient(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Fingerprint: test:x\n", encoding="utf-8")
    env = _install_fakes(tmp_path, view_label=False, view_type=False, sticky_miss=True)
    proc = _run(
        "issue-create",
        "--title",
        "ci-gap: test -- example",
        "--body-file",
        str(body),
        env=env,
    )
    assert proc.returncode == 2
    assert "after repair" in proc.stderr
    assert "issues/99" in proc.stderr
    assert "do not create a duplicate" in proc.stderr


def test_issue_create_rejects_malformed_create_output(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Fingerprint: test:x\n", encoding="utf-8")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gitleaks = bindir / "gitleaks"
    gitleaks.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gh = bindir / "gh"
    gh.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        '  "issue create")\n'
        '    if echo "$*" | grep -q -- "--jq"; then echo ""; fi\n'
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 1\n",
        encoding="utf-8",
    )
    gitleaks.chmod(gitleaks.stat().st_mode | stat.S_IEXEC)
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    proc = _run(
        "issue-create",
        "--title",
        "ci-gap: test -- example",
        "--body-file",
        str(body),
        env=env,
    )
    assert proc.returncode == 2
    assert "unexpected output" in proc.stderr
