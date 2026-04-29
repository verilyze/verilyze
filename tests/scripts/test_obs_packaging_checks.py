# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for OBS packaging consistency wiring."""

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_makefile_exposes_check_obs_packaging_target() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert ".PHONY: check-obs-packaging" in text
    assert "check-obs-packaging:" in text


def test_makefile_check_depends_on_obs_packaging_validation() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "check-obs-packaging" in text


def test_obs_project_env_has_required_coordinate_keys() -> None:
    env_file = _repo_root() / "packaging" / "obs" / "obs-project.env"
    text = env_file.read_text(encoding="utf-8")
    assert "OBS_PROJECT=" in text
    assert "OBS_PACKAGE=" in text


def test_obs_packaging_check_script_invokes_signing_check() -> None:
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "check-obs-signing.sh" in text


def test_obs_packaging_check_does_not_require_ripgrep() -> None:
    """GitHub Actions ubuntu-latest images do not install ripgrep by default."""
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "rg " not in text
