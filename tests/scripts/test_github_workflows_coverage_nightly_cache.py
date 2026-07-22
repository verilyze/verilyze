# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: coverage-nightly rust-cache aligns with ci.yml check job."""

from pathlib import Path

from tests.scripts.repo_root import repo_root

_COVERAGE_NIGHTLY = repo_root() / ".github" / "workflows" / "coverage-nightly.yml"


def _coverage_job_block() -> str:
    text = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    start = text.index("  coverage-wiki-badges:")
    end = text.index("      - name: Set up Python", start)
    return text[start:end]


def test_coverage_nightly_job_sets_linker_env_at_job_level() -> None:
    block = _coverage_job_block()
    assert "env:" in block
    assert "CC: gcc" in block
    assert "RUSTFLAGS: -Clink-arg=-fuse-ld=bfd" in block


def test_coverage_nightly_rust_cache_uses_shared_key_check() -> None:
    text = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    assert "shared-key: check" in text


def test_coverage_nightly_publish_badges_passes_step_outcome() -> None:
    text = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    start = text.index("      - name: Publish coverage badges to wiki")
    end = text.index("      - name: Fail job when coverage did not succeed", start)
    block = text[start:end]
    assert "COVERAGE_STEP_OUTCOME: ${{ steps.coverage.outcome }}" in block
