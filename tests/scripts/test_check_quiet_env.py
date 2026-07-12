# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: quiet and verbose log env for CI check and coverage test runs."""

import subprocess

from tests.scripts.repo_root import repo_root

_QUIET_ENV = repo_root() / "scripts" / "lib" / "check-quiet-env.sh"
_CI = repo_root() / ".github" / "workflows" / "ci.yml"
_RUN_CHECK = repo_root() / "scripts" / "run-check.sh"


def _bash_env(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )


def test_check_quiet_env_exports_off_and_never() -> None:
    text = _QUIET_ENV.read_text(encoding="utf-8")
    assert "VLZ_QUIET_RUST_LOG=off" in text
    assert "VLZ_QUIET_RUST_LOG_STYLE=never" in text
    assert "VLZ_VERBOSE_RUST_LOG=info" in text
    assert "vlz_check_verbose_enabled" in text
    assert "vlz_apply_check_log_env" in text


def test_apply_check_log_env_quiet_by_default() -> None:
    result = _bash_env(
        "source scripts/lib/check-quiet-env.sh && "
        "vlz_apply_check_log_env && "
        "printf '%s %s' \"$RUST_LOG\" \"$RUST_LOG_STYLE\""
    )
    assert result.returncode == 0
    assert result.stdout == "off never"


def test_apply_check_log_env_verbose_when_check_verbose_set() -> None:
    result = _bash_env(
        "source scripts/lib/check-quiet-env.sh && "
        "VLZ_CHECK_VERBOSE=1 vlz_apply_check_log_env && "
        "printf '%s %s' \"$RUST_LOG\" \"$RUST_LOG_STYLE\""
    )
    assert result.returncode == 0
    assert result.stdout == "info auto"


def test_cargo_test_quiet_arg_omitted_when_verbose() -> None:
    result = _bash_env(
        "source scripts/lib/check-quiet-env.sh && "
        "VLZ_CHECK_VERBOSE=1 vlz_cargo_test_quiet_arg | wc -c"
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "0"


def test_cargo_test_quiet_arg_present_when_quiet() -> None:
    result = _bash_env(
        "source scripts/lib/check-quiet-env.sh && vlz_cargo_test_quiet_arg"
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "--quiet"


def test_run_check_sources_check_quiet_env() -> None:
    text = _RUN_CHECK.read_text(encoding="utf-8")
    assert "check-quiet-env.sh" in text
    assert "vlz_apply_check_log_env" in text
    assert "VLZ_CHECK_VERBOSE" in text
    assert "RUST_LOG=error" not in text


def test_build_matrix_library_tests_use_quiet_log_env() -> None:
    text = _CI.read_text(encoding="utf-8")
    start = text.index("  build-matrix:")
    end = text.index("  check:", start)
    block = text[start:end]
    lib = block.index("Run vlz library tests")
    step = block[lib : lib + 400]
    assert "RUST_LOG: off" in step
    assert "RUST_LOG_STYLE: never" in step
    assert "--quiet" in step


def test_check_job_sets_verbose_from_runner_debug() -> None:
    text = _CI.read_text(encoding="utf-8")
    start = text.index("  check:")
    end = text.index("  coverage-pr-comment:", start)
    block = text[start:end]
    run = block.index("Run make -j check")
    step = block[run : run + 300]
    assert "VLZ_CHECK_VERBOSE:" in step
    assert "runner.debug" in step
    assert "./scripts/run-check.sh" in step
