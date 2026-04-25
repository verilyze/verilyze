# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for renovate.json (super-linter digest, GitHub Actions, scoped managers)."""

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent


def test_renovate_json_exists_and_parses() -> None:
    path = _ROOT / "renovate.json"
    assert path.is_file(), "renovate.json must exist at repository root"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data.get("$schema")


def test_renovate_regex_managers_use_delimited_file_patterns() -> None:
    """Renovate treats managerFilePatterns as globs unless wrapped in /.../."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    for mgr in data.get("customManagers", []):
        if mgr.get("customType") != "regex":
            continue
        for pat in mgr.get("managerFilePatterns", []):
            assert pat.startswith("/") and pat.endswith("/"), (
                f"pattern must be /.../ regex form so paths match: {pat!r}"
            )


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


def test_enabled_managers_include_dockerfile_custom_regex_github_actions() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    em = data.get("enabledManagers", [])
    assert "dockerfile" in em
    assert "custom.regex" in em
    assert "github-actions" in em
    assert "pip_requirements" in em


def test_renovate_extends_pin_github_action_digests() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    extends = data.get("extends", [])
    assert "helpers:pinGitHubActionDigests" in extends


def test_renovate_extends_git_sign_off_for_dco() -> None:
    """Renovate must add Signed-off-by so PRs pass scripts/check-dco.sh in CI."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    extends = data.get("extends", [])
    assert ":gitSignOff" in extends


def test_renovate_rebase_when_behind_base_branch() -> None:
    """Keep PR branches rebased when main moves (staleness reduction)."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    assert data.get("rebaseWhen") == "behind-base-branch"


def test_renovate_platform_automerge_uses_github_native_merge() -> None:
    """Use GitHub auto-merge after required checks; pairs with repo branch settings."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    assert data.get("platformAutomerge") is True


def test_renovate_pr_concurrent_limit() -> None:
    """Cap open Renovate PRs to reduce parallel stale branches."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    assert data.get("prConcurrentLimit") == 3


def test_renovate_automerge_non_major_via_package_rules() -> None:
    """Automerge safe update types only; majors need manual merge."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    merge_on = next(
        (
            r
            for r in rules
            if r.get("description", "").startswith("Enable GitHub platform auto-merge")
            and r.get("automerge") is True
        ),
        None,
    )
    assert merge_on is not None
    types = merge_on.get("matchUpdateTypes", [])
    assert "major" not in types
    assert "minor" in types and "patch" in types
    major_off = next(
        (
            r
            for r in rules
            if r.get("description", "").startswith("Major updates require manual")
            and r.get("automerge") is False
        ),
        None,
    )
    assert major_off is not None
    assert major_off.get("matchUpdateTypes") == ["major"]


def test_renovate_package_rule_groups_reuse_lockfile() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    match = next(
        (
            r
            for r in rules
            if r.get("groupName") == "reuse-tooling-pip"
            and r.get("matchManagers") == ["pip_requirements"]
            and r.get("matchFileNames") == ["scripts/requirements-reuse.txt"]
        ),
        None,
    )
    assert match is not None, (
        "packageRules must group scripts/requirements-reuse.txt "
        "under reuse-tooling-pip"
    )


def test_renovate_package_rule_groups_github_actions_minor_patch() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    match = next(
        (
            r
            for r in rules
            if r.get("groupName") == "github-actions-minor-patch"
            and r.get("matchManagers") == ["github-actions"]
            and r.get("matchUpdateTypes") == ["minor", "patch"]
        ),
        None,
    )
    assert match is not None, (
        "packageRules must group github-actions minor and patch updates "
        "under groupName github-actions-minor-patch"
    )


def test_renovate_workflow_uses_github_app_token() -> None:
    """Renovate workflow should authenticate via GitHub App, not GITHUB_TOKEN."""
    workflow = (_ROOT / ".github" / "workflows" / "renovate.yml").read_text(
        encoding="utf-8"
    )
    assert "create-github-app-token" in workflow
    assert "client-id:" in workflow
    assert "RENOVATE_APP_CLIENT_ID" in workflow
    assert "RENOVATE_APP_PRIVATE_KEY" in workflow
    assert "app-id:" not in workflow
    assert "RENOVATE_APP_ID" not in workflow
    assert "steps.renovate-token.outputs.token" in workflow.replace(" ", "")
    assert "github.token" not in workflow


def test_renovate_workflow_sets_repository_target() -> None:
    """Renovate must receive RENOVATE_REPOSITORIES or it logs No repositories found."""
    workflow = (_ROOT / ".github" / "workflows" / "renovate.yml").read_text(
        encoding="utf-8"
    )
    assert "RENOVATE_REPOSITORIES" in workflow
    assert "github.repository" in workflow


def test_renovate_workflow_scheduled_twice_weekly() -> None:
    """Scheduled Renovate runs twice per week at 05:00 UTC (Monday and Thursday)."""
    workflow = (_ROOT / ".github" / "workflows" / "renovate.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count("cron:") == 2
    assert 'cron: "0 5 * * 1"' in workflow
    assert 'cron: "0 5 * * 4"' in workflow
