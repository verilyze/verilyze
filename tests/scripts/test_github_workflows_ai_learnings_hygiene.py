# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Structural tests for .github/workflows/ai-learnings-issue-hygiene.yml."""

from pathlib import Path

from tests.scripts.repo_root import repo_root

_WORKFLOW = (
    repo_root() / ".github" / "workflows" / "ai-learnings-issue-hygiene.yml"
)


def test_ai_learnings_hygiene_triggers_on_issues() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "issues:" in text
    assert "types: [opened]" in text
    assert "edited" not in text.split("types:")[1].split("\n", 1)[0]


def test_ai_learnings_hygiene_applies_label_and_type() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "--add-label ai-learnings" in text
    assert "--type Learning" in text
    assert "ci-gap|agent):" in text
    assert "## Fingerprint" in text
    assert "## Classification" in text
