# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/generate-and-push-coverage-badges.sh decision logic."""

import os
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_SCRIPT = repo_root() / "scripts" / "generate-and-push-coverage-badges.sh"

_MIN_COBERTURA = """<?xml version="1.0" ?>
<coverage line-rate="0.8533" branch-rate="0" version="1.9" timestamp="" lines-covered="1" lines-valid="1">
  <packages/>
</coverage>
"""


def _run_badge_script(
    tmp_path: Path,
    *,
    outcome: str | None = "success",
    rust_xml: bool = True,
    python_xml: bool = True,
) -> subprocess.CompletedProcess[str]:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    if rust_xml:
        (reports / "cobertura-rust.xml").write_text(_MIN_COBERTURA, encoding="utf-8")
    if python_xml:
        (reports / "cobertura-python.xml").write_text(_MIN_COBERTURA, encoding="utf-8")

    env = {
        **os.environ,
        "COVERAGE_BADGE_REPO_ROOT": str(tmp_path),
        "COVERAGE_BADGE_SKIP_PUSH": "1",
    }
    if outcome is not None:
        env["COVERAGE_STEP_OUTCOME"] = outcome
    else:
        env.pop("COVERAGE_STEP_OUTCOME", None)

    return subprocess.run(
        [str(_SCRIPT)],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_success_with_both_cobertura_files_writes_percent_badges(
    tmp_path: Path,
) -> None:
    result = _run_badge_script(tmp_path, outcome="success")
    assert result.returncode == 0, result.stderr
    rust_svg = (tmp_path / "coverage-rust.svg").read_text(encoding="utf-8")
    python_svg = (tmp_path / "coverage-python.svg").read_text(encoding="utf-8")
    assert "85.33%" in rust_svg
    assert "85.33%" in python_svg


def test_default_outcome_success_writes_percent_badges(tmp_path: Path) -> None:
    result = _run_badge_script(tmp_path, outcome=None)
    assert result.returncode == 0, result.stderr
    assert "%" in (tmp_path / "coverage-rust.svg").read_text(encoding="utf-8")


def test_failure_outcome_writes_unknown_badges(tmp_path: Path) -> None:
    result = _run_badge_script(tmp_path, outcome="failure")
    assert result.returncode == 1
    assert "coverage step did not succeed" in result.stderr
    rust_svg = (tmp_path / "coverage-rust.svg").read_text(encoding="utf-8")
    assert ">unknown</text>" in rust_svg
    assert "85.33%" not in rust_svg


def test_missing_cobertura_writes_unknown_badges(tmp_path: Path) -> None:
    result = _run_badge_script(
        tmp_path, outcome="success", rust_xml=False, python_xml=False
    )
    assert result.returncode == 1
    assert "incomplete Cobertura reports" in result.stderr
    assert "unknown" in (tmp_path / "coverage-rust.svg").read_text(encoding="utf-8")


def test_partial_cobertura_writes_unknown_badges(tmp_path: Path) -> None:
    result = _run_badge_script(
        tmp_path, outcome="success", rust_xml=True, python_xml=False
    )
    assert result.returncode == 1
    assert "incomplete Cobertura reports" in result.stderr
    assert "unknown" in (tmp_path / "coverage-python.svg").read_text(encoding="utf-8")


def test_failure_and_missing_xml_mentions_both_reasons(tmp_path: Path) -> None:
    result = _run_badge_script(
        tmp_path, outcome="failure", rust_xml=False, python_xml=False
    )
    assert result.returncode == 1
    assert "coverage step did not succeed" in result.stderr
    assert "incomplete Cobertura reports" in result.stderr
