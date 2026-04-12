# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Subprocess tests for CI input validation in shell scripts (OP-019, NFR-021)."""

import os
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
_CHECK_DCO = _ROOT / "scripts" / "check-dco.sh"
_CHECK_SIG = _ROOT / "scripts" / "check-signatures.sh"
_EXTRACT_CL = _ROOT / "scripts" / "extract-changelog-for-release.sh"


def _run_script(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        argv,
        cwd=cwd,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


def _head_sha(cwd: Path) -> str:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout.strip()


class TestCheckDcoMergeGroupSha40:
    """check-dco.sh: strict SHA40 only when GITHUB_EVENT_NAME is merge_group."""

    def test_merge_group_rejects_branch_name_before_git(self) -> None:
        proc = _run_script(
            [str(_CHECK_DCO), "main", "HEAD"],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "merge_group"},
        )
        assert proc.returncode == 1
        combined = proc.stderr + proc.stdout
        assert "40" in combined or "hex" in combined.lower() or "sha" in combined.lower()

    def test_merge_group_accepts_full_shas_same_commit(self) -> None:
        sha = _head_sha(_ROOT)
        proc = _run_script(
            [str(_CHECK_DCO), sha, sha],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "merge_group"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_merge_group_accepts_uppercase_hex_after_normalize(self) -> None:
        sha = _head_sha(_ROOT)
        upper = sha.upper()
        proc = _run_script(
            [str(_CHECK_DCO), upper, upper],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "merge_group"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_merge_group_accepts_padded_whitespace(self) -> None:
        sha = _head_sha(_ROOT)
        proc = _run_script(
            [str(_CHECK_DCO), f"  {sha}  ", sha],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "merge_group"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_non_merge_group_allows_head_head_refs(self) -> None:
        proc = _run_script(
            [str(_CHECK_DCO), "HEAD", "HEAD"],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "pull_request"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_non_merge_group_unset_event_allows_head_head(self) -> None:
        child_env = {k: v for k, v in os.environ.items() if k != "GITHUB_EVENT_NAME"}
        proc = subprocess.run(
            [str(_CHECK_DCO), "HEAD", "HEAD"],
            cwd=_ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout


class TestCheckSignaturesMergeGroupSha40:
    """check-signatures.sh: same merge_group gate for two-arg mode."""

    def test_merge_group_rejects_non_sha40(self) -> None:
        proc = _run_script(
            [str(_CHECK_SIG), "--presence-only", "main", "HEAD"],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "merge_group"},
        )
        assert proc.returncode == 1
        combined = proc.stderr + proc.stdout
        assert "40" in combined or "hex" in combined.lower() or "sha" in combined.lower()

    def test_merge_group_accepts_full_shas_same_commit(self) -> None:
        sha = _head_sha(_ROOT)
        proc = _run_script(
            [str(_CHECK_SIG), "--presence-only", sha, sha],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "merge_group"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout

    def test_non_merge_group_allows_head_head(self) -> None:
        proc = _run_script(
            [str(_CHECK_SIG), "--presence-only", "HEAD", "HEAD"],
            cwd=_ROOT,
            env={"GITHUB_EVENT_NAME": "pull_request"},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout


class TestExtractChangelogSemver:
    """extract-changelog-for-release.sh: SemVer allow-list before awk."""

    def test_valid_version_emits_section(self) -> None:
        proc = _run_script(
            [str(_EXTRACT_CL), "0.1.0"],
            cwd=_ROOT,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "## [0.1.0]" in proc.stdout

    def test_invalid_with_v_prefix_exits_2(self) -> None:
        proc = _run_script(
            [str(_EXTRACT_CL), "v1.0.0"],
            cwd=_ROOT,
        )
        assert proc.returncode == 2
        assert proc.stderr

    def test_invalid_garbage_exits_2(self) -> None:
        proc = _run_script(
            [str(_EXTRACT_CL), "not-a-version"],
            cwd=_ROOT,
        )
        assert proc.returncode == 2
        assert proc.stderr

    def test_prerelease_allowed_when_section_exists(self) -> None:
        proc = _run_script(
            [str(_EXTRACT_CL), "0.1.0-rc.1", str(_ROOT / "CHANGELOG.md")],
            cwd=_ROOT,
        )
        # Section may not exist; exit 1 from awk is OK. SemVer must be valid.
        if proc.returncode == 2:
            pytest.fail("valid semver must not be rejected: " + proc.stderr)
        assert proc.returncode in (0, 1)
