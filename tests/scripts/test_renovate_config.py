# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for renovate.json (super-linter digest regex, scoped managers)."""

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent


def test_renovate_json_exists_and_parses() -> None:
    path = _ROOT / "renovate.json"
    assert path.is_file(), "renovate.json must exist at repository root"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data.get("$schema")


def test_renovate_super_linter_regex_manager() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    managers = data.get("customManagers", [])
    assert len(managers) >= 1
    slm = managers[0]
    assert slm.get("customType") == "regex"
    patterns = slm.get("managerFilePatterns", [])
    assert any("super-linter" in p for p in patterns)
    assert slm.get("datasourceTemplate") == "docker"
    assert slm.get("packageNameTemplate") == "ghcr.io/super-linter/super-linter"
    assert slm.get("currentValueTemplate") == "slim-latest"
    match_strings = slm.get("matchStrings", [])
    assert match_strings
    assert "currentDigest" in match_strings[0]
    assert "SL_SHA=" in match_strings[0]


def test_super_linter_script_sl_sha_matches_digest_line_regex() -> None:
    """Keep scripts/super-linter.sh aligned with renovate.json matchStrings."""
    text = (_ROOT / "scripts" / "super-linter.sh").read_text(encoding="utf-8")
    assert re.search(
        r'^SL_SHA="sha256:[a-f0-9]+"$',
        text,
        re.MULTILINE,
    ), "SL_SHA must be a single pinned digest line for Renovate regex manager"


def test_enabled_managers_scope_dockerfile_and_custom_regex() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    em = data.get("enabledManagers", [])
    assert "dockerfile" in em
    assert "custom.regex" in em


def test_renovate_workflow_uses_github_app_token() -> None:
    """Renovate workflow should authenticate via GitHub App, not GITHUB_TOKEN."""
    workflow = (_ROOT / ".github" / "workflows" / "renovate.yml").read_text(
        encoding="utf-8"
    )
    assert "create-github-app-token" in workflow
    assert "RENOVATE_APP_ID" in workflow
    assert "RENOVATE_APP_PRIVATE_KEY" in workflow
    assert "steps.renovate-token.outputs.token" in workflow.replace(" ", "")
    assert "github.token" not in workflow
