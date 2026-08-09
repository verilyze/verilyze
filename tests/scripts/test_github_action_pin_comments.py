# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for scripts/github_action_pin_comments.py."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.github_action_pin_comments import (
    FULL_SEMVER_TAG_RE,
    check_pin_comments,
    find_pin_comment_issues,
    get_repo_root,
    main,
)
from tests.scripts.repo_root import repo_root

_ROOT = repo_root()

_SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


class TestFullSemverConstant:
    def test_accepts_v_x_y_z(self) -> None:
        assert FULL_SEMVER_TAG_RE.fullmatch("v2.9.2")
        assert FULL_SEMVER_TAG_RE.fullmatch("v7.0.1")

    def test_rejects_major_or_major_minor(self) -> None:
        assert FULL_SEMVER_TAG_RE.fullmatch("v2") is None
        assert FULL_SEMVER_TAG_RE.fullmatch("v2.9") is None


class TestFindPinCommentIssues:
    def test_full_semver_passes(self) -> None:
        text = f"""\
jobs:
  check:
    steps:
      - uses: actions/checkout@{_SHA_A} # v7.0.1
        uses: Swatinem/rust-cache@{_SHA_B} # v2.9.2
"""
        assert find_pin_comment_issues(text, path="wf.yml") == []

    def test_zizmor_ignore_suffix_allowed(self) -> None:
        text = f"""\
jobs:
  release:
    steps:
      - uses: softprops/action-gh-release@{_SHA_A} # v3.0.2  # zizmor: ignore[superfluous-actions]
"""
        assert find_pin_comment_issues(text, path="release.yml") == []

    def test_major_only_comment_fails(self) -> None:
        text = f"""\
jobs:
  check:
    steps:
      - uses: Swatinem/rust-cache@{_SHA_A} # v2
"""
        findings = find_pin_comment_issues(text, path="ci.yml")
        assert len(findings) == 1
        assert findings[0].path == "ci.yml"
        assert findings[0].line == 4
        assert "v2" in findings[0].message

    def test_major_minor_comment_fails(self) -> None:
        text = f"""\
jobs:
  check:
    steps:
      - uses: actions/checkout@{_SHA_A} # v7.0
"""
        findings = find_pin_comment_issues(text, path="ci.yml")
        assert len(findings) == 1
        assert "v7.0" in findings[0].message

    def test_missing_comment_fails(self) -> None:
        text = f"""\
jobs:
  check:
    steps:
      - uses: actions/checkout@{_SHA_A}
"""
        findings = find_pin_comment_issues(text, path="ci.yml")
        assert len(findings) == 1
        assert "missing" in findings[0].message.lower()

    def test_bare_hash_comment_fails(self) -> None:
        text = f"      - uses: actions/checkout@{_SHA_A} #\n"
        findings = find_pin_comment_issues(text, path="ci.yml")
        assert len(findings) == 1
        assert "missing" in findings[0].message.lower()

    def test_whitespace_only_hash_comment_fails(self) -> None:
        text = f"      - uses: actions/checkout@{_SHA_A} #   \n"
        findings = find_pin_comment_issues(text, path="ci.yml")
        assert len(findings) == 1
        assert "missing" in findings[0].message.lower()

    def test_hash_without_leading_space_passes(self) -> None:
        text = f"      - uses: actions/checkout@{_SHA_A}# v7.0.1\n"
        assert find_pin_comment_issues(text, path="ci.yml") == []

    def test_prerelease_tag_fails(self) -> None:
        text = f"      - uses: actions/checkout@{_SHA_A} # v7.0.1-rc.1\n"
        findings = find_pin_comment_issues(text, path="ci.yml")
        assert len(findings) == 1
        assert "v7.0.1-rc.1" in findings[0].message

    def test_skips_reusable_workflow_job_uses(self) -> None:
        text = f"""\
jobs:
  provenance:
    uses: org/repo/.github/workflows/generator.yml@{_SHA_A}
"""
        assert find_pin_comment_issues(text, path="release.yml") == []

    def test_skips_non_sha_refs(self) -> None:
        text = """\
jobs:
  check:
    steps:
      - uses: actions/checkout@v4
"""
        assert find_pin_comment_issues(text, path="ci.yml") == []


class TestCheckPinComments:
    def test_check_pin_comments_scans_workflows_and_examples(
        self, tmp_path: Path
    ) -> None:
        wf = tmp_path / ".github" / "workflows" / "ci.yml"
        ex = tmp_path / "examples" / "demo.yml"
        wf.parent.mkdir(parents=True)
        ex.parent.mkdir(parents=True)
        wf.write_text(
            f"      - uses: actions/checkout@{_SHA_A} # v7.0.1\n",
            encoding="utf-8",
        )
        ex.write_text(
            f"      - uses: actions/checkout@{_SHA_B} # v2\n",
            encoding="utf-8",
        )
        findings = check_pin_comments(tmp_path)
        assert len(findings) == 1
        assert findings[0].path.endswith("examples/demo.yml")

    def test_check_pin_comments_clean_tree(self, tmp_path: Path) -> None:
        wf = tmp_path / ".github" / "workflows" / "ci.yml"
        wf.parent.mkdir(parents=True)
        wf.write_text(
            f"      - uses: actions/checkout@{_SHA_A} # v7.0.1\n",
            encoding="utf-8",
        )
        assert check_pin_comments(tmp_path) == []


class TestGetRepoRoot:
    def test_get_repo_root_points_at_workspace(self) -> None:
        root = get_repo_root()
        assert (root / "scripts" / "github_action_pin_comments.py").is_file()


class TestMain:
    def test_main_check_fails_on_findings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wf = tmp_path / ".github" / "workflows" / "ci.yml"
        wf.parent.mkdir(parents=True)
        wf.write_text(
            f"      - uses: Swatinem/rust-cache@{_SHA_A} # v2\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "scripts.github_action_pin_comments.get_repo_root",
            lambda: tmp_path,
        )
        assert main(["--check"]) == 1

    def test_main_check_passes_when_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wf = tmp_path / ".github" / "workflows" / "ci.yml"
        wf.parent.mkdir(parents=True)
        wf.write_text(
            f"      - uses: actions/checkout@{_SHA_A} # v7.0.1\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "scripts.github_action_pin_comments.get_repo_root",
            lambda: tmp_path,
        )
        assert main(["--check"]) == 0

    def test_main_requires_check_flag(self) -> None:
        with pytest.raises(SystemExit):
            main([])

    def test_module_entry_point(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(_ROOT)}
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.github_action_pin_comments",
                "--check",
            ],
            cwd=_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0

    def test_script_entry_point(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(_ROOT)}
        proc = subprocess.run(
            [
                sys.executable,
                str(_ROOT / "scripts" / "github_action_pin_comments.py"),
                "--check",
            ],
            cwd=_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0

    def test_skips_non_file_glob_hits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = tmp_path / ".github" / "workflows" / "gone.yml"
        monkeypatch.setattr(
            "scripts.github_action_pin_comments._iter_scan_paths",
            lambda _root: [missing],
        )
        assert check_pin_comments(tmp_path) == []
