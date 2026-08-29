# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Tests for scripts/sync_vlz_build_metadata.py."""

import subprocess
from pathlib import Path

import pytest

from scripts.sync_vlz_build_metadata import (
    get_repo_root,
    main,
    render_build_metadata,
)


def test_get_repo_root_contains_scripts() -> None:
    root = get_repo_root()
    assert (root / "scripts" / "sync_vlz_build_metadata.py").is_file()


def test_render_build_metadata_from_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.verilyze]\n"
        "line-length = 88\n"
        "\n"
        "[tool.vlz-headers]\n"
        'default_copyright = "Example Contributors"\n'
        'default_license = "MIT"\n',
        encoding="utf-8",
    )
    rendered = render_build_metadata(pyproject)
    assert "line-length = 88" in rendered
    assert "default_copyright = 'Example Contributors'" in rendered
    assert "default_license = 'MIT'" in rendered
    assert "SPDX-License-Identifier: GPL-3.0-or-later" in rendered


def test_render_build_metadata_defaults_when_tool_sections_missing(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n", encoding="utf-8")
    rendered = render_build_metadata(pyproject)
    assert "line-length = 79" in rendered
    assert "default_copyright = 'The verilyze contributors'" in rendered
    assert "default_license = 'GPL-3.0-or-later'" in rendered


def test_render_build_metadata_defaults_when_tool_values_not_dicts(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool]\nverilyze = 'nope'\nvlz-headers = 'nope'\n",
        encoding="utf-8",
    )
    rendered = render_build_metadata(pyproject)
    assert "line-length = 79" in rendered
    assert "default_copyright = 'The verilyze contributors'" in rendered


def test_main_check_passes_when_in_sync() -> None:
    assert main(["--check"]) == 0


def test_main_check_fails_when_out_of_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import sync_vlz_build_metadata as mod

    (tmp_path / "pyproject.toml").write_text(
        "[tool.verilyze]\nline-length = 79\n",
        encoding="utf-8",
    )
    out = tmp_path / "crates" / "core" / "vlz"
    out.mkdir(parents=True)
    (out / "build-metadata.toml").write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(mod, "get_repo_root", lambda: tmp_path)
    assert main(["--check"]) == 1


def test_main_writes_build_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import sync_vlz_build_metadata as mod

    (tmp_path / "pyproject.toml").write_text(
        "[tool.verilyze]\nline-length = 100\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "crates" / "core" / "vlz"
    out_dir.mkdir(parents=True)
    monkeypatch.setattr(mod, "get_repo_root", lambda: tmp_path)
    assert main([]) == 0
    written = (out_dir / "build-metadata.toml").read_text(encoding="utf-8")
    assert "line-length = 100" in written


def test_main_check_treats_missing_output_as_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import sync_vlz_build_metadata as mod

    (tmp_path / "pyproject.toml").write_text(
        "[tool.verilyze]\nline-length = 79\n",
        encoding="utf-8",
    )
    (tmp_path / "crates" / "core" / "vlz").mkdir(parents=True)
    monkeypatch.setattr(mod, "get_repo_root", lambda: tmp_path)
    assert main(["--check"]) == 1


def test_main_as_module_exits_with_check_status() -> None:
    root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [
            str(root / ".venv-test/bin/python"),
            str(root / "scripts" / "sync_vlz_build_metadata.py"),
            "--check",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0

# REUSE-IgnoreEnd
