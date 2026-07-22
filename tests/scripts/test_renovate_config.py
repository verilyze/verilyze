# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Structural tests for renovate.json (regex managers, super-linter digest)."""

import json
import re
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()


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


def test_renovate_osv_vulnerability_alerts_enabled() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    assert data.get("osvVulnerabilityAlerts") is True


def test_renovate_pep621_pypi_range_strategy_bump() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    match = next(
        (
            r
            for r in rules
            if r.get("matchManagers") == ["pep621"]
            and r.get("matchDatasources") == ["pypi"]
            and r.get("matchFileNames") == ["pyproject.toml"]
            and r.get("rangeStrategy") == "bump"
        ),
        None,
    )
    assert match is not None, (
        "packageRules must set rangeStrategy bump for pep621 PyPI deps "
        "in pyproject.toml"
    )


def test_renovate_pep621_post_upgrade_regenerates_sbom() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    match = next(
        (
            r
            for r in rules
            if r.get("matchManagers") == ["pep621"]
            and r.get("matchFileNames") == ["pyproject.toml"]
            and "postUpgradeTasks" in r
        ),
        None,
    )
    assert match is not None, (
        "packageRules must run postUpgradeTasks for pep621 pyproject.toml"
    )
    tasks = match["postUpgradeTasks"]
    assert tasks["commands"] == ["bash scripts/renovate-post-upgrade-sbom.sh"]
    assert tasks["fileFilters"] == ["pylock.dev.toml", "sbom/**"]
    assert tasks["executionMode"] == "branch"
    tools = tasks["installTools"]
    assert "rust" in tools
    assert "python" in tools, (
        "pep621 postUpgradeTasks need python so ensure-reuse.sh can run "
        "check-headers during make generate-sbom"
    )


def test_renovate_cargo_post_upgrade_commits_sbom() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    match = next(
        (
            r
            for r in rules
            if r.get("matchManagers") == ["cargo"] and "postUpgradeTasks" in r
        ),
        None,
    )
    assert match is not None
    filters = match["postUpgradeTasks"]["fileFilters"]
    assert "THIRD-PARTY-LICENSES" in filters
    assert "sbom/**" in filters


def test_renovate_cargo_deny_manager_matches_ci_env_and_coverage_nightly() -> None:
    """Renovate must bump CARGO_DENY_VERSION in ci.yml and coverage-nightly pin."""
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    managers = data.get("customManagers", [])
    deny = next(
        (
            m
            for m in managers
            if m.get("depNameTemplate") == "cargo-deny"
            and m.get("datasourceTemplate") == "crate"
        ),
        None,
    )
    assert deny is not None, "customManagers must include cargo-deny regex manager"
    patterns = deny.get("managerFilePatterns", [])
    assert any("ci\\.yml" in p for p in patterns)
    assert any("coverage-nightly" in p for p in patterns)
    match_strings = deny.get("matchStrings", [])
    assert any("CARGO_DENY_VERSION" in s for s in match_strings)
    assert any("cargo-deny@" in s for s in match_strings)
    ci_yml = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    env_match = re.search(r'CARGO_DENY_VERSION: "([^"]+)"', ci_yml)
    assert env_match is not None
    nightly = (
        _ROOT / ".github" / "workflows" / "coverage-nightly.yml"
    ).read_text(encoding="utf-8")
    assert f"cargo-deny@{env_match.group(1)}" in nightly


def test_renovate_package_rule_groups_cargo_deny_workflow_pins() -> None:
    data = json.loads((_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = data.get("packageRules", [])
    match = next(
        (
            r
            for r in rules
            if r.get("groupName") == "cargo-deny-workflow-pins"
            and r.get("matchPackageNames") == ["cargo-deny"]
        ),
        None,
    )
    assert match is not None, (
        "packageRules must group cargo-deny pins under cargo-deny-workflow-pins"
    )


def test_renovate_workflow_allows_post_upgrade_sbom_script() -> None:
    text = (_ROOT / ".github/workflows/renovate.yml").read_text(encoding="utf-8")
    assert "renovate-post-upgrade-sbom" in text
    assert "renovate-post-upgrade-licenses" in text
