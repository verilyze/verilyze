# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for RPM spec synchronization tooling."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_sync_rpm_specs_check_mode_succeeds_for_committed_files() -> None:
    """The committed local RPM spec must match generated output."""
    script = _repo_root() / "scripts" / "sync_rpm_specs.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--check"],
        cwd=_repo_root(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_makefile_exposes_and_uses_check_rpm_spec_sync_target() -> None:
    """CI-facing targets should include RPM spec sync verification."""
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert ".PHONY: sync-rpm-specs check-rpm-spec-sync" in text
    assert "check-packaging: check-rpm-spec-sync" in text


def test_obs_readme_documents_dual_spec_sync_workflow() -> None:
    """Contributor docs should define how to keep dual specs in sync."""
    text = (_repo_root() / "packaging" / "obs" / "README.md").read_text(
        encoding="utf-8"
    )
    assert "make sync-rpm-specs" in text
    assert "make check-rpm-spec-sync" in text
    assert "RPM dual-spec maintenance" in text
    assert "source of truth for OBS builds" in text


def test_local_spec_includes_shared_check_section_from_obs() -> None:
    """Local spec should carry shared %check logic from OBS source spec."""
    text = (
        _repo_root() / "packaging" / "rpm" / "SPECS" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "\n%check\n" in text
    assert "./target/release/%{crate_name} --version" in text
    assert "./target/release/%{crate_name} --help >/dev/null" in text
