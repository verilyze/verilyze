# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for GitHub SARIF upload workflows (SEC-015)."""

import re
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_NIGHTLY = _ROOT / ".github" / "workflows" / "verilyze-nightly.yml"
_SUPPLY_CHAIN = _ROOT / ".github" / "workflows" / "supply-chain.yml"
_EXAMPLE = _ROOT / "examples" / "github-action-vlz-scan.yml"
_UPLOAD_SARIF_SHA = "7188fc363630916deb702c7fdcf4e481b751f97a"
_CATEGORY = "verilyze-sca"


def _verilyze_job_block(workflow_text: str) -> str:
    match = re.search(
        r"^\s{2}verilyze:\n(?:(?:^\s{4}.+\n)|(?:^\s{2}\S.+\n))*",
        workflow_text,
        re.MULTILINE,
    )
    assert match is not None, "verilyze job block not found"
    return match.group(0)


class TestVerilyzeNightlySarifWorkflow:
    def test_nightly_uploads_sarif_with_category(self) -> None:
        text = _NIGHTLY.read_text(encoding="utf-8")
        job = _verilyze_job_block(text)
        assert "security-events: write" in job
        assert f"github/codeql-action/upload-sarif@{_UPLOAD_SARIF_SHA}" in job
        assert f"category: {_CATEGORY}" in job

    def test_nightly_uses_best_available_reachability(self) -> None:
        text = _NIGHTLY.read_text(encoding="utf-8")
        assert "VLZ_REACHABILITY_MODE: best-available" in text

    def test_nightly_upload_steps_run_on_always(self) -> None:
        text = _NIGHTLY.read_text(encoding="utf-8")
        sarif_upload = re.search(
            r"- name: Upload verilyze SARIF to code scanning\n\s+if: >-\n([\s\S]*?)\n\s+uses:",
            text,
        )
        assert sarif_upload is not None
        assert "always()" in sarif_upload.group(1)
        artifact_upload = re.search(
            r"- name: Upload verilyze scan reports\n\s+if: >-\n([\s\S]*?)\n\s+uses:",
            text,
        )
        assert artifact_upload is not None
        assert "always()" in artifact_upload.group(1)

    def test_nightly_scan_continues_on_error_then_enforces_exit(self) -> None:
        text = _NIGHTLY.read_text(encoding="utf-8")
        assert "continue-on-error: true" in text
        assert "ci-enforce-scan-exit.sh" in text

    def test_nightly_verifies_release_binary_version(self) -> None:
        text = _NIGHTLY.read_text(encoding="utf-8")
        assert "ci-verify-vlz-release-version.sh" in text


class TestSupplyChainSarifWorkflow:
    def test_supply_chain_upload_only_on_same_repo_pr(self) -> None:
        text = _SUPPLY_CHAIN.read_text(encoding="utf-8")
        job = _verilyze_job_block(text)
        assert f"github/codeql-action/upload-sarif@{_UPLOAD_SARIF_SHA}" in job
        upload_match = re.search(
            r"- name: Upload verilyze SARIF to code scanning\n\s+if: >-\n([\s\S]*?)\n\s+uses:",
            text,
        )
        assert upload_match is not None
        condition = upload_match.group(1)
        assert "github.event_name == 'pull_request'" in condition
        assert (
            "github.event.pull_request.head.repo.full_name == github.repository"
            in condition
        )

    def test_supply_chain_does_not_upload_on_push_main(self) -> None:
        text = _SUPPLY_CHAIN.read_text(encoding="utf-8")
        upload_match = re.search(
            r"- name: Upload verilyze SARIF to code scanning\n\s+if: >-\n([\s\S]*?)\n\s+uses:",
            text,
        )
        assert upload_match is not None
        condition = upload_match.group(1)
        assert "github.event_name == 'pull_request'" in condition

    def test_supply_chain_artifact_upload_uses_always(self) -> None:
        text = _SUPPLY_CHAIN.read_text(encoding="utf-8")
        artifact_upload = re.search(
            r"- name: Upload verilyze scan reports\n\s+if: >-\n([\s\S]*?)\n\s+uses:",
            text,
        )
        assert artifact_upload is not None
        assert "always()" in artifact_upload.group(1)


class TestGithubActionVlzScanExample:
    def test_example_documents_upload_and_fork_guard(self) -> None:
        text = _EXAMPLE.read_text(encoding="utf-8")
        assert f"github/codeql-action/upload-sarif@{_UPLOAD_SARIF_SHA}" in text
        assert f"category: {_CATEGORY}" in text
        assert "continue-on-error: true" in text
        assert "github.event.pull_request.head.repo.full_name" in text
        assert "VLZ_REACHABILITY_MODE" in text
        assert "actions: read" in text
