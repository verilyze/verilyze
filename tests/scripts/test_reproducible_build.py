# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for NFR-006 reproducible build helpers (HC-6)."""

import os
import stat
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_ENV_SH = _ROOT / "scripts" / "lib" / "reproducible-build-env.sh"
_CHECK_SH = _ROOT / "scripts" / "check-reproducible-build.sh"
_MAKEFILE = _ROOT / "Makefile"
_RELEASE_WORKFLOW = _ROOT / ".github" / "workflows" / "release.yml"
_NIGHTLY_WORKFLOW = _ROOT / ".github" / "workflows" / "reproducible-build-nightly.yml"
_VERBOSE_ENV_KEYS = ("VLZ_CHECK_VERBOSE", "VLZ_COVERAGE_VERBOSE")


def _base_env(**overrides: str) -> dict[str, str]:
    env = dict(os.environ)
    for key in _VERBOSE_ENV_KEYS:
        env.pop(key, None)
    env.update(overrides)
    return env


def test_reproducible_env_sets_source_date_epoch_and_remap() -> None:
    proc = subprocess.run(
        [
            "bash",
            "-c",
            (
                f'source "{_ENV_SH}"; '
                f'vlz_apply_reproducible_build_env "{_ROOT}"; '
                'printf "%s\\n" "$SOURCE_DATE_EPOCH"; '
                'printf "%s\\n" "$CARGO_INCREMENTAL"; '
                'printf "%s\\n" "$RUSTFLAGS"'
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=_ROOT,
        env=_base_env(),
    )
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == 3
    assert lines[0].isdigit()
    assert int(lines[0]) > 0
    assert lines[1] == "0"
    assert f"--remap-path-prefix={_ROOT}=/build" in lines[2]


def test_reproducible_env_preserves_existing_source_date_epoch() -> None:
    proc = subprocess.run(
        [
            "bash",
            "-c",
            (
                f'source "{_ENV_SH}"; '
                f'vlz_apply_reproducible_build_env "{_ROOT}"; '
                'printf "%s\\n" "$SOURCE_DATE_EPOCH"'
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=_ROOT,
        env=_base_env(SOURCE_DATE_EPOCH="12345"),
    )
    assert proc.stdout.strip() == "12345"


def test_reproducible_env_appends_remap_to_existing_rustflags() -> None:
    proc = subprocess.run(
        [
            "bash",
            "-c",
            (
                f'source "{_ENV_SH}"; '
                f'vlz_apply_reproducible_build_env "{_ROOT}"; '
                'printf "%s\\n" "$RUSTFLAGS"'
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=_ROOT,
        env=_base_env(RUSTFLAGS="-Dwarnings"),
    )
    flags = proc.stdout.strip()
    assert flags.startswith("-Dwarnings")
    assert f"--remap-path-prefix={_ROOT}=/build" in flags


def test_check_reproducible_build_quiet_match(tmp_path: Path) -> None:
    fake_cargo = tmp_path / "cargo"
    fake_cargo.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'mkdir -p "${CARGO_TARGET_DIR}/release"\n'
        'printf "identical\\n" > "${CARGO_TARGET_DIR}/release/vlz"\n',
        encoding="utf-8",
    )
    fake_cargo.chmod(fake_cargo.stat().st_mode | stat.S_IXUSR)
    env = _base_env()
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"
    proc = subprocess.run(
        ["bash", str(_CHECK_SH)],
        check=False,
        capture_output=True,
        text=True,
        cwd=_ROOT,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_check_reproducible_build_fails_on_mismatch(tmp_path: Path) -> None:
    fake_cargo = tmp_path / "cargo"
    fake_cargo.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'mkdir -p "${CARGO_TARGET_DIR}/release"\n'
        'printf "%s\\n" "${CARGO_TARGET_DIR}" > "${CARGO_TARGET_DIR}/release/vlz"\n',
        encoding="utf-8",
    )
    fake_cargo.chmod(fake_cargo.stat().st_mode | stat.S_IXUSR)
    env = _base_env()
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"
    proc = subprocess.run(
        ["bash", str(_CHECK_SH)],
        check=False,
        capture_output=True,
        text=True,
        cwd=_ROOT,
        env=env,
    )
    assert proc.returncode == 1
    assert "reproducible build mismatch" in proc.stderr


def test_makefile_has_check_reproducible_build_leaf() -> None:
    text = _MAKEFILE.read_text(encoding="utf-8")
    assert "check-reproducible-build:" in text
    assert "check-reproducible-build.sh" in text
    assert "MAKE_RUN_LEAF) check-reproducible-build" in text
    fast_start = text.index("check-fast-parallel:")
    fast_end = text.index("\ncheck:", fast_start)
    assert "check-reproducible-build" not in text[fast_start:fast_end]


def test_release_workflow_applies_reproducible_env() -> None:
    text = _RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "reproducible-build-env.sh" in text
    assert "vlz_apply_reproducible_build_env" in text


def test_nightly_workflow_runs_check_reproducible_build() -> None:
    assert _NIGHTLY_WORKFLOW.is_file()
    text = _NIGHTLY_WORKFLOW.read_text(encoding="utf-8")
    assert "make check-reproducible-build" in text
    assert "NFR-006" in text
