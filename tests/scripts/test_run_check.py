# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/run-check.sh failure summary extraction."""

import subprocess

from tests.scripts.repo_root import repo_root

_RUN_CHECK = repo_root() / "scripts" / "run-check.sh"
_BANNER = "=== verilyze check failure summary ==="


def _summarize(log_text: str) -> subprocess.CompletedProcess[str]:
    fixture = repo_root() / "target" / "test-run-check-log.txt"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(log_text, encoding="utf-8")
    return subprocess.run(
        [_RUN_CHECK, "--summarize-log", str(fixture)],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )


def test_summarize_log_extracts_unique_failed_targets() -> None:
    log = """
clippy output...
make[2]: *** [clippy] Error 101
more output
make[1]: *** [lint-python] Error 1
make[2]: *** [clippy] Error 101
"""
    result = _summarize(log)
    assert result.returncode == 0
    assert _BANNER in result.stderr
    assert "Failed make target(s) (2):" in result.stderr
    assert "  - clippy" in result.stderr
    assert "  - lint-python" in result.stderr
    assert "  make clippy" in result.stderr
    assert "  make lint-python" in result.stderr


def test_summarize_log_omits_aggregate_targets_from_rerun_hints() -> None:
    log = """
make: *** [check-parallel] Error 2
make[2]: *** [fmt-check] Error 1
"""
    result = _summarize(log)
    assert result.returncode == 0
    assert "  - check-parallel" in result.stderr
    assert "  - fmt-check" in result.stderr
    assert "make check-parallel" not in result.stderr
    assert "  make fmt-check" in result.stderr


def test_summarize_log_strips_makefile_line_prefix_from_target() -> None:
    log = "make[2]: *** [Makefile:335: coverage-quick] Error 101\n"
    result = _summarize(log)
    assert result.returncode == 0
    assert "  - coverage-quick" in result.stderr
    assert "Makefile:335" not in result.stderr
    assert "  make coverage-quick" in result.stderr


def test_summarize_log_no_failures_is_silent() -> None:
    result = _summarize("all good\n")
    assert result.returncode == 0
    assert result.stderr == ""


def test_run_check_script_exists_and_is_executable() -> None:
    assert _RUN_CHECK.is_file()
    assert _RUN_CHECK.stat().st_mode & 0o111
