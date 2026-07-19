# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/run-check-command.sh brief CI output."""

import os
import shutil
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_RUN_CMD = repo_root() / "scripts" / "run-check-command.sh"
_SUMMARIZE = repo_root() / "scripts" / "run-check.sh"
_BANNER = "=== verilyze check failure summary ==="
_DIAG_HEADER = "Failed command diagnostic(s):"


def _bash(script: str, **env: str) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **env}
    return subprocess.run(
        ["bash", "-c", script],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


def _run_cmd(
    label: str,
    *cmd: str,
    results_dir: Path | None = None,
    verbose: str = "",
    brief: str = "1",
) -> subprocess.CompletedProcess[str]:
    env: dict[str, str] = {"VLZ_CHECK_BRIEF": brief}
    if results_dir is not None:
        env["VLZ_CHECK_RESULTS_DIR"] = str(results_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
    if verbose:
        env["VLZ_CHECK_VERBOSE"] = verbose
    argv = [str(_RUN_CMD), label, "--", *cmd]
    return subprocess.run(
        argv,
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **env},
    )


def test_brief_success_suppresses_tool_output() -> None:
    results = repo_root() / "target" / "test-check-results-success"
    if results.exists():
        shutil.rmtree(results)
    result = _run_cmd(
        "echo-test",
        "bash",
        "-c",
        "echo noisy success line",
        results_dir=results,
    )
    assert result.returncode == 0
    assert "[RUN] echo-test" in result.stdout
    assert "[PASS] echo-test" in result.stdout
    assert "noisy success line" not in result.stdout
    assert not list((results / "failures").glob("*")) if (results / "failures").is_dir() else True


def test_brief_failure_replays_and_preserves_exit_code() -> None:
    results = repo_root() / "target" / "test-check-results-fail"
    if results.exists():
        shutil.rmtree(results)
    result = _run_cmd(
        "fail-test",
        "bash",
        "-c",
        "echo diagnostic line >&2; exit 42",
        results_dir=results,
    )
    assert result.returncode == 42
    assert "[FAIL] fail-test (exit 42)" in result.stdout
    assert "diagnostic line" in result.stdout
    meta_files = list((results / "failures").glob("*.meta"))
    assert len(meta_files) == 1
    assert "label=fail-test" in meta_files[0].read_text(encoding="utf-8")
    assert "exit_code=42" in meta_files[0].read_text(encoding="utf-8")


def test_verbose_streams_child_output() -> None:
    result = _run_cmd(
        "verbose-test",
        "bash",
        "-c",
        "echo streamed line",
        verbose="1",
    )
    assert result.returncode == 0
    assert "streamed line" in result.stdout


def test_summarize_includes_bounded_command_diagnostics() -> None:
    results = repo_root() / "target" / "test-check-results-summary"
    failures = results / "failures"
    failures.mkdir(parents=True, exist_ok=True)
    (failures / "001-clippy.meta").write_text(
        "label=clippy\nexit_code=101\n", encoding="utf-8"
    )
    (failures / "001-clippy.log").write_text(
        "error: clippy found a problem\n", encoding="utf-8"
    )
    log = repo_root() / "target" / "test-run-check-log-diag.txt"
    log.write_text("make[2]: *** [clippy] Error 101\n", encoding="utf-8")
    result = subprocess.run(
        [
            str(_SUMMARIZE),
            "--summarize-log",
            str(log),
            "--results-dir",
            str(results),
        ],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert _BANNER in result.stderr
    assert _DIAG_HEADER in result.stderr
    assert "clippy (exit 101)" in result.stderr
    assert "error: clippy found a problem" in result.stderr


def test_summarize_omits_diagnostics_without_results_dir() -> None:
    log = repo_root() / "target" / "test-run-check-log-no-results.txt"
    log.write_text("make[1]: *** [fmt-check] Error 1\n", encoding="utf-8")
    result = subprocess.run(
        [_SUMMARIZE, "--summarize-log", str(log)],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert _DIAG_HEADER not in result.stderr


def test_brief_check_brief_enabled_unless_verbose() -> None:
    off = _bash(
        "source scripts/lib/check-quiet-env.sh && "
        "vlz_check_brief_enabled && echo yes || echo no",
        VLZ_CHECK_BRIEF="0",
    )
    assert off.stdout.strip() == "no"
    on = _bash(
        "source scripts/lib/check-quiet-env.sh && "
        "VLZ_CHECK_BRIEF=1 vlz_check_brief_enabled && echo yes || echo no"
    )
    assert on.stdout.strip() == "yes"
    verbose = _bash(
        "source scripts/lib/check-quiet-env.sh && "
        "VLZ_CHECK_VERBOSE=1 vlz_check_brief_enabled && echo yes || echo no"
    )
    assert verbose.stdout.strip() == "no"


def test_malformed_runner_invocation_exits_2() -> None:
    no_sep = subprocess.run(
        [str(_RUN_CMD), "label", "echo", "hi"],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert no_sep.returncode == 2
    assert "usage:" in no_sep.stderr

    no_cmd = subprocess.run(
        [str(_RUN_CMD), "label", "--"],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert no_cmd.returncode == 2
    assert "usage:" in no_cmd.stderr


def test_multiple_failures_produce_distinct_captures_and_excerpts() -> None:
    results = repo_root() / "target" / "test-check-results-multi"
    if results.exists():
        shutil.rmtree(results)
    first = _run_cmd(
        "fail-a",
        "bash",
        "-c",
        "echo diag-a; exit 3",
        results_dir=results,
    )
    second = _run_cmd(
        "fail-b",
        "bash",
        "-c",
        "echo diag-b; exit 4",
        results_dir=results,
    )
    assert first.returncode == 3
    assert second.returncode == 4
    meta_files = sorted((results / "failures").glob("*.meta"))
    assert len(meta_files) == 2
    log = repo_root() / "target" / "test-run-check-log-multi.txt"
    log.write_text(
        "make[1]: *** [fail-a] Error 3\nmake[1]: *** [fail-b] Error 4\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(_SUMMARIZE),
            "--summarize-log",
            str(log),
            "--results-dir",
            str(results),
        ],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "fail-a (exit 3)" in result.stderr
    assert "fail-b (exit 4)" in result.stderr
    assert "diag-a" in result.stderr
    assert "diag-b" in result.stderr


def test_success_with_error_text_does_not_record_failure() -> None:
    results = repo_root() / "target" / "test-check-results-neg"
    if results.exists():
        shutil.rmtree(results)
    result = _run_cmd(
        "neg-test",
        "bash",
        "-c",
        "echo 'ERROR: expected negative path'; exit 0",
        results_dir=results,
    )
    assert result.returncode == 0
    assert "[PASS] neg-test" in result.stdout
    assert "ERROR: expected negative path" not in result.stdout
    failures = results / "failures"
    assert not failures.is_dir() or not list(failures.glob("*"))


def test_meta_shell_metacharacters_do_not_execute() -> None:
    results = repo_root() / "target" / "test-check-results-meta-safe"
    if results.exists():
        shutil.rmtree(results)
    results.mkdir(parents=True, exist_ok=True)
    marker = results / "pwned"
    if marker.exists():
        marker.unlink()
    # Literal shell metacharacters in the label (not expanded by Python).
    label = "evil-$(touch " + str(marker) + ")"
    result = _run_cmd(
        label,
        "bash",
        "-c",
        "echo boom; exit 7",
        results_dir=results,
    )
    assert result.returncode == 7
    assert not marker.exists()
    log = repo_root() / "target" / "test-run-check-log-meta-safe.txt"
    log.write_text("make[1]: *** [evil] Error 7\n", encoding="utf-8")
    summarize = subprocess.run(
        [
            str(_SUMMARIZE),
            "--summarize-log",
            str(log),
            "--results-dir",
            str(results),
        ],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert summarize.returncode == 0
    assert not marker.exists()
    assert "evil-$(touch" in summarize.stderr
    assert "boom" in summarize.stderr


def test_diagnostic_excerpt_truncates_long_capture() -> None:
    results = repo_root() / "target" / "test-check-results-trunc"
    failures = results / "failures"
    failures.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"line-{i}" for i in range(100))
    (failures / "001-long.meta").write_text(
        "label=long\nexit_code=1\n", encoding="utf-8"
    )
    (failures / "001-long.log").write_text(body + "\n", encoding="utf-8")
    log = repo_root() / "target" / "test-run-check-log-trunc.txt"
    log.write_text("make[1]: *** [long] Error 1\n", encoding="utf-8")
    result = subprocess.run(
        [
            str(_SUMMARIZE),
            "--summarize-log",
            str(log),
            "--results-dir",
            str(results),
        ],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "long (exit 1)" in result.stderr
    assert "truncated; see full log above" in result.stderr
    assert "line-99" not in result.stderr


def test_brief_off_streams_without_capture() -> None:
    result = subprocess.run(
        [
            str(_RUN_CMD),
            "stream-test",
            "--",
            "bash",
            "-c",
            "echo streamed-brief-off",
        ],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "VLZ_CHECK_BRIEF": "0"},
    )
    assert result.returncode == 0
    assert "streamed-brief-off" in result.stdout


def test_lint_python_aggregates_scanner_failures(tmp_path: Path) -> None:
    lint = repo_root() / "scripts" / "lint-python.sh"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then echo "Python 3.13"; exit 0; fi\n'
        "echo modern-ok\n"
        "exit 0\n",
        encoding="utf-8",
    )
    for name, fail in (
        ("black", "1"),
        ("pylint", "0"),
        ("mypy", "1"),
        ("bandit", "0"),
    ):
        path = bin_dir / name
        path.write_text(
            "#!/bin/sh\n"
            f'if [ "${{1:-}}" = "--version" ]; then echo "{name} 1"; exit 0; fi\n'
            f"echo {name}-out\n"
            f"exit {fail}\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
    (bin_dir / "python3").chmod(0o755)
    result = subprocess.run(
        [str(lint)],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "VENV_BIN": str(bin_dir),
            "VLZ_CHECK_BRIEF": "1",
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        },
    )
    assert result.returncode == 1
    out = result.stdout
    assert "[RUN] python-modern-style" in out
    assert "[PASS] python-modern-style" in out
    assert "[FAIL] black" in out
    assert "[RUN] pylint" in out
    assert "[PASS] pylint" in out
    assert "[FAIL] mypy" in out
    assert "[RUN] bandit" in out
    assert "[PASS] bandit" in out
