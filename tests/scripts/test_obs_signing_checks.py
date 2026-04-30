# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS signing verification script behavior."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPT = _ROOT / "scripts" / "check-obs-signing.sh"


def _run_script(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_obs_env(tmp_path: Path) -> Path:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "OBS_PROJECT=home:tpost:verilyze",
                "OBS_PACKAGE=verilyze",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return env_file


def _write_signing_keys_html(
    tmp_path: Path,
    *,
    include_fingerprint: bool = True,
    expires_on: str = "2030-01-01",
) -> Path:
    key_bits = []
    if include_fingerprint:
        key_bits.append(
            (
                "<dt class='col-12 col-sm-3'>Fingerprint</dt>"
                "<dd class='col-12 col-sm-9 font-monospace'>"
                "aa11 bb22 cc33 dd44 ee55 ff66 1122 3344 5566 7788"
                "</dd>"
            )
        )
    key_bits.append(
        (
            "<dt class='col-6 col-sm-3'>Expires on</dt>"
            f"<dd class='col-6 col-sm-9 small'>{expires_on}</dd>"
        )
    )
    signing_file = tmp_path / "signing_keys.html"
    signing_file.write_text(
        "\n".join(
            [
                "<html><body>",
                "<h3>Signing Keys</h3>",
                *key_bits,
                "</body></html>",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return signing_file


def test_obs_signing_check_accepts_valid_metadata(tmp_path: Path) -> None:
    env_file = _write_obs_env(tmp_path)
    signing_file = _write_signing_keys_html(tmp_path)

    proc = _run_script(
        [
            str(_SCRIPT),
            "--config",
            str(env_file),
            "--signing-keys-file",
            str(signing_file),
            "--min-valid-days",
            "30",
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "fingerprint=" in output


def test_obs_signing_check_fails_without_fingerprint(tmp_path: Path) -> None:
    env_file = _write_obs_env(tmp_path)
    signing_file = _write_signing_keys_html(
        tmp_path,
        include_fingerprint=False,
    )

    proc = _run_script(
        [
            str(_SCRIPT),
            "--config",
            str(env_file),
            "--signing-keys-file",
            str(signing_file),
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "fingerprint" in output.lower()


def test_obs_signing_check_fails_when_key_expires_too_soon(
    tmp_path: Path,
) -> None:
    env_file = _write_obs_env(tmp_path)
    expires_on = (datetime.now(UTC) + timedelta(days=5)).date().isoformat()
    signing_file = _write_signing_keys_html(tmp_path, expires_on=expires_on)

    proc = _run_script(
        [
            str(_SCRIPT),
            "--config",
            str(env_file),
            "--signing-keys-file",
            str(signing_file),
            "--min-valid-days",
            "30",
        ]
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "expires" in output.lower()
