# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for scripts/upload_sarif_pins.py."""

from pathlib import Path

import pytest

from scripts.upload_sarif_pins import (
    EXAMPLE_WORKFLOW,
    SUPPLY_CHAIN_WORKFLOW,
    UPLOAD_SARIF_REF_RE,
    UPLOAD_SARIF_USES_RE,
    canonical_ref,
    canonical_uses_line,
    sync_example,
)
from tests.scripts.repo_root import repo_root

_ROOT = repo_root()

_SUPPLY_CHAIN_FIXTURE = """\
jobs:
  verilyze:
    steps:
      - name: Upload verilyze SARIF to code scanning
        uses: github/codeql-action/upload-sarif@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0
"""

_EXAMPLE_FIXTURE = """\
jobs:
  scan:
    steps:
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v0.9.0
  rescan:
    steps:
      - name: Upload SARIF again
        uses: github/codeql-action/upload-sarif@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v0.9.0
"""


class TestCanonicalRef:
    def test_canonical_ref_returns_first_pin(self) -> None:
        ref = canonical_ref(_SUPPLY_CHAIN_FIXTURE)
        assert ref == (
            "github/codeql-action/upload-sarif@"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )

    def test_canonical_ref_missing_raises(self) -> None:
        with pytest.raises(SystemExit, match="missing upload-sarif pin"):
            canonical_ref("jobs: {}")


class TestCanonicalUsesLine:
    def test_canonical_uses_line_includes_version_comment(self) -> None:
        line = canonical_uses_line(_SUPPLY_CHAIN_FIXTURE)
        assert line == (
            "uses: github/codeql-action/upload-sarif@"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0"
        )


class TestSyncExample:
    def test_sync_example_updates_all_pins(self, tmp_path: Path) -> None:
        supply = tmp_path / SUPPLY_CHAIN_WORKFLOW
        example = tmp_path / EXAMPLE_WORKFLOW
        supply.parent.mkdir(parents=True)
        example.parent.mkdir(parents=True)
        supply.write_text(_SUPPLY_CHAIN_FIXTURE, encoding="utf-8")
        example.write_text(_EXAMPLE_FIXTURE, encoding="utf-8")

        changed = sync_example(tmp_path)
        assert changed is True
        updated = example.read_text(encoding="utf-8")
        assert (
            "uses: github/codeql-action/upload-sarif@"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0"
        ) in updated
        assert "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" not in updated
        assert len(UPLOAD_SARIF_REF_RE.findall(updated)) == 2

    def test_sync_example_noop_when_aligned(self, tmp_path: Path) -> None:
        supply = tmp_path / SUPPLY_CHAIN_WORKFLOW
        example = tmp_path / EXAMPLE_WORKFLOW
        supply.parent.mkdir(parents=True)
        example.parent.mkdir(parents=True)
        supply.write_text(_SUPPLY_CHAIN_FIXTURE, encoding="utf-8")
        aligned = _EXAMPLE_FIXTURE.replace(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v0.9.0",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0",
        )
        example.write_text(aligned, encoding="utf-8")

        changed = sync_example(tmp_path)
        assert changed is False

    def test_sync_example_check_fails_when_drift(self, tmp_path: Path) -> None:
        supply = tmp_path / SUPPLY_CHAIN_WORKFLOW
        example = tmp_path / EXAMPLE_WORKFLOW
        supply.parent.mkdir(parents=True)
        example.parent.mkdir(parents=True)
        supply.write_text(_SUPPLY_CHAIN_FIXTURE, encoding="utf-8")
        example.write_text(_EXAMPLE_FIXTURE, encoding="utf-8")

        assert sync_example(tmp_path, check=True) is True

    def test_sync_example_check_passes_when_aligned(
        self, tmp_path: Path
    ) -> None:
        supply = tmp_path / SUPPLY_CHAIN_WORKFLOW
        example = tmp_path / EXAMPLE_WORKFLOW
        supply.parent.mkdir(parents=True)
        example.parent.mkdir(parents=True)
        supply.write_text(_SUPPLY_CHAIN_FIXTURE, encoding="utf-8")
        aligned = _EXAMPLE_FIXTURE.replace(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v0.9.0",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0",
        )
        example.write_text(aligned, encoding="utf-8")

        changed = sync_example(tmp_path, check=True)
        assert changed is False


class TestRepoContract:
    def test_committed_example_matches_supply_chain(self) -> None:
        assert sync_example(_ROOT, check=True) is False

    def test_uses_regex_matches_supply_chain_line(self) -> None:
        text = (_ROOT / SUPPLY_CHAIN_WORKFLOW).read_text(encoding="utf-8")
        match = UPLOAD_SARIF_USES_RE.search(text)
        assert match is not None
