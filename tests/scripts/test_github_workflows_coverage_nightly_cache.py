# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: coverage-nightly rust-cache aligns with ci.yml check job."""

import re

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


def test_coverage_nightly_cargo_afl_pin_matches_ci() -> None:
    """Nightly must use the same cargo-afl pin as ci.yml Install cargo-afl."""
    ci = (repo_root() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    nightly = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    # ci.yml: dedicated step; nightly: combined tool: line
    ci_match = re.search(r"cargo-afl@([^\s,]+)", ci)
    assert ci_match is not None, "ci.yml must pin cargo-afl@"
    assert f"cargo-afl@{ci_match.group(1)}" in nightly, (
        f"coverage-nightly must pin cargo-afl@{ci_match.group(1)} to match ci.yml"
    )


def test_coverage_nightly_cargo_about_pin_matches_ci() -> None:
    """Nightly must use the same cargo-about pin as ci.yml install-action."""
    ci = (repo_root() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    nightly = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    ci_match = re.search(r"cargo-about@([^\s,]+)", ci)
    assert ci_match is not None, "ci.yml must pin cargo-about@"
    assert f"cargo-about@{ci_match.group(1)}" in nightly, (
        f"coverage-nightly must pin cargo-about@{ci_match.group(1)} to match ci.yml"
    )


def test_coverage_nightly_cargo_llvm_cov_pin_matches_ci() -> None:
    """Nightly must use the same cargo-llvm-cov pin as ci.yml install-action."""
    ci = (repo_root() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    nightly = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    ci_match = re.search(r"cargo-llvm-cov@([^\s,]+)", ci)
    assert ci_match is not None, "ci.yml must pin cargo-llvm-cov@"
    assert f"cargo-llvm-cov@{ci_match.group(1)}" in nightly, (
        f"coverage-nightly must pin cargo-llvm-cov@{ci_match.group(1)} to match ci.yml"
    )


def test_coverage_nightly_sets_afl_verbose_on_coverage_step() -> None:
    text = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    start = text.index(
        "      - name: Run make coverage-extended (fuzz + optional features + Cobertura)"
    )
    end = text.index("      - name: Publish coverage badges to wiki", start)
    block = text[start:end]
    assert 'VLZ_AFL_VERBOSE: "1"' in block


def test_coverage_nightly_apt_installs_llvm_dev() -> None:
    text = _COVERAGE_NIGHTLY.read_text(encoding="utf-8")
    start = text.index("      - name: Install ShellCheck and AFL++")
    end = text.index("      - name: Install gitleaks", start)
    block = text[start:end]
    assert "llvm-dev" in block
    assert "afl++" in block
