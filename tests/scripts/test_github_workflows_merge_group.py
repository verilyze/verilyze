# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Merge queue on main requires merge_group triggers in key workflows."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CODEQL = _ROOT / ".github" / "workflows" / "codeql.yml"
_SCORECARD_PR = _ROOT / ".github" / "workflows" / "scorecard-pr.yml"


def test_ci_workflow_triggers_merge_group_checks_requested() -> None:
    text = _CI.read_text(encoding="utf-8")
    assert "merge_group:" in text
    assert "checks_requested" in text


def test_ci_workflow_runs_dco_and_signatures_on_merge_group_shas() -> None:
    text = _CI.read_text(encoding="utf-8")
    assert "github.event.merge_group.base_sha" in text
    assert "github.event.merge_group.head_sha" in text
    assert "check-dco.sh" in text
    assert "check-signatures.sh" in text


def test_codeql_workflow_triggers_merge_group_checks_requested() -> None:
    text = _CODEQL.read_text(encoding="utf-8")
    assert "merge_group:" in text
    assert "checks_requested" in text


def test_scorecard_pr_workflow_does_not_use_merge_group() -> None:
    """scorecard-pr stays PR-only; merge_group is intentionally omitted."""
    text = _SCORECARD_PR.read_text(encoding="utf-8")
    assert "merge_group" not in text
