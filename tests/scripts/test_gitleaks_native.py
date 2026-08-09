# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/gitleaks_native.py (workdir scan + redact)."""

import shutil
from pathlib import Path

import pytest

from scripts import gitleaks_native
from tests.scripts.repo_root import repo_root

# Split markers so this test module is not itself a gitleaks hit.
_PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
_PEM_END = "-----END " + "RSA PRIVATE KEY-----"
_PEM_BODY = "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFw=="


def _private_key_fixture() -> str:
    return f"{_PEM_BEGIN}\n{_PEM_BODY}\n{_PEM_END}\n"


def test_build_gitleaks_directory_cmd_matches_super_linter_shape() -> None:
    scan = Path("/tmp/scan-root")
    config = Path("/tmp/scan-root/.gitleaks.toml")
    cmd = gitleaks_native.build_gitleaks_directory_cmd(scan, config)
    assert cmd == [
        "gitleaks",
        "directory",
        "--no-banner",
        "--redact",
        "--verbose",
        "--config",
        str(config),
        str(scan),
    ]


def test_run_gitleaks_directory_fails_on_workdir_secret(
    tmp_path: Path,
) -> None:
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks not installed")

    root = repo_root()
    config = root / gitleaks_native.GITLEAKS_CONFIG_NAME
    assert config.is_file()

    secret = tmp_path / "leak.pem"
    secret.write_text(_private_key_fixture(), encoding="utf-8")

    code, output = gitleaks_native.run_gitleaks_directory(tmp_path, config)
    assert code != 0
    assert "BEGIN RSA PRIVATE KEY" not in output
    assert "REDACTED" in output or "leaks found" in output.lower()


def test_run_gitleaks_directory_missing_binary_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gitleaks_native.shutil, "which", lambda _name: None)
    config = tmp_path / gitleaks_native.GITLEAKS_CONFIG_NAME
    config.write_text("title = 't'\n", encoding="utf-8")
    code, output = gitleaks_native.run_gitleaks_directory(tmp_path, config)
    assert code != 0
    assert "gitleaks" in output.lower()


def test_main_usage_extra_args() -> None:
    assert gitleaks_native.main(["a", "b"]) == 2


def test_main_missing_config(tmp_path: Path) -> None:
    assert gitleaks_native.main([str(tmp_path)]) == 1


def test_main_success_writes_output_without_trailing_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / gitleaks_native.GITLEAKS_CONFIG_NAME
    config.write_text("title = 't'\n", encoding="utf-8")

    def _fake_run(_scan: Path, _config: Path) -> tuple[int, str]:
        return 0, "ok"

    monkeypatch.setattr(gitleaks_native, "run_gitleaks_directory", _fake_run)
    assert gitleaks_native.main([str(tmp_path)]) == 0
    assert capsys.readouterr().err.endswith("\n")


def test_main_default_root(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _fake_run(scan: Path, config: Path) -> tuple[int, str]:
        assert scan == Path(gitleaks_native.__file__).resolve().parents[1]
        assert config.name == gitleaks_native.GITLEAKS_CONFIG_NAME
        return 0, "done\n"

    monkeypatch.setattr(gitleaks_native, "run_gitleaks_directory", _fake_run)
    assert gitleaks_native.main([]) == 0
    assert "done" in capsys.readouterr().err


def test_report_missing_gitleaks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(gitleaks_native.shutil, "which", lambda _name: None)
    assert gitleaks_native.report_missing_gitleaks() == 1
    err = capsys.readouterr().err
    assert "gitleaks is required" in err
