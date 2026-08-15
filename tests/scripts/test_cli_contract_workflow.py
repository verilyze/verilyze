# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for .github/workflows/cli-contract.yml."""

from tests.scripts.repo_root import repo_root

_WF = repo_root() / ".github" / "workflows" / "cli-contract.yml"


def test_cli_contract_workflow_is_path_filtered() -> None:
    text = _WF.read_text(encoding="utf-8")
    assert "tests/cli_contract/**" in text
    assert "crates/**" in text
    assert "fail-fast: false" in text
    assert "ubuntu-latest" in text
    assert "macos-latest" in text
    assert "windows-latest" in text
    assert "CLI_CONTRACT" not in text.split("jobs:")[0]
    assert "contents: write" not in text
    assert "schedule:" in text
    assert "scripts/cli_contract.py" in text
    assert "cli-contract-python.sh" in text
    assert "smoke | full" in text
    assert "DISPATCH_MODE:" in text
    assert 'mode="${{ github.event.inputs.mode' not in text
