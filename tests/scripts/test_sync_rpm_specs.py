# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Tests for RPM spec synchronization tooling."""

import importlib.util
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.scripts.repo_root import repo_root

_script_path = repo_root() / "scripts" / "sync_rpm_specs.py"
_spec = importlib.util.spec_from_file_location("sync_rpm_specs", _script_path)
sync_rpm_specs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync_rpm_specs)  # type: ignore[union-attr]

MIN_OBS_SPEC = """%global crate_name vlz
%global pkg_name verilyze

Name:           %{pkg_name}
Version:        1.2.3
Release:        0%{?dist}
Source0:        %{pkg_name}-%{version}.tar.xz
Source1:        vendor.tar.zst
BuildRequires:  zstd

%prep
# Unpack OBS cargo_vendor tarball; it overlays .cargo, vendor/, and Cargo.lock.
tar --zstd -xf %{SOURCE1}

%build
cargo build --release --locked --offline

%install
install -D foo bar
"""


def _setup_spec_tree(
    tmp_path: Path, obs_text: str, local_text: str
) -> None:
    obs_path = tmp_path / sync_rpm_specs.OBS_SPEC_PATH
    local_path = tmp_path / sync_rpm_specs.LOCAL_SPEC_PATH
    obs_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    obs_path.write_text(obs_text, encoding="utf-8")
    local_path.write_text(local_text, encoding="utf-8")


class TestRepoRoot:
    def test_returns_parent_of_scripts(self) -> None:
        root = sync_rpm_specs._repo_root()
        assert (root / "scripts" / "sync_rpm_specs.py").exists()
        assert root.name != "scripts"


class TestExtractObsVersion:
    def test_parses_semver(self) -> None:
        assert sync_rpm_specs._extract_obs_version(MIN_OBS_SPEC) == "1.2.3"

    def test_raises_when_version_missing(self) -> None:
        with pytest.raises(ValueError, match="Unable to parse OBS spec Version"):
            sync_rpm_specs._extract_obs_version("Name: test\n")


class TestRenderLocalSpec:
    def test_applies_all_transformations(self) -> None:
        result = sync_rpm_specs.render_local_spec(MIN_OBS_SPEC)
        assert "Version:        %{version}" in result
        assert "%{!?version:%global version 1.2.3}" in result
        assert "Release:        1%{?dist}" in result
        assert "Source0:        %{pkg_name}-%{version}.tar.gz" in result
        assert "cargo build --release --locked\n" in result
        assert "Source1:" not in result
        assert "Source2:" not in result
        assert "BuildRequires:  zstd" not in result
        assert "tar --zstd" not in result
        assert sync_rpm_specs.LOCAL_INSERTION in result
        assert "\n%install\n" in result

    def test_skips_insertion_when_already_present(self) -> None:
        obs = MIN_OBS_SPEC.replace(
            "\n%install\n",
            f"\n{sync_rpm_specs.LOCAL_INSERTION}\n%install\n",
            1,
        )
        result = sync_rpm_specs.render_local_spec(obs)
        assert result.count(sync_rpm_specs.LOCAL_INSERTION) == 1

    def test_skips_insertion_when_install_section_missing(self) -> None:
        obs = MIN_OBS_SPEC.replace("\n%install\n", "\n%files\n")
        result = sync_rpm_specs.render_local_spec(obs)
        assert sync_rpm_specs.LOCAL_INSERTION not in result


class TestWriteIfChanged:
    def test_returns_false_when_unchanged(self, tmp_path: Path) -> None:
        path = tmp_path / "spec"
        path.write_text("same\n", encoding="utf-8")
        assert sync_rpm_specs._write_if_changed(path, "same\n") is False
        assert path.read_text(encoding="utf-8") == "same\n"

    def test_returns_true_when_updated(self, tmp_path: Path) -> None:
        path = tmp_path / "spec"
        path.write_text("old\n", encoding="utf-8")
        assert sync_rpm_specs._write_if_changed(path, "new\n") is True
        assert path.read_text(encoding="utf-8") == "new\n"


class TestRenderDiff:
    def test_includes_expected_and_actual_labels(self) -> None:
        diff = sync_rpm_specs._render_diff(
            "a\n", "b\n", sync_rpm_specs.LOCAL_SPEC_PATH
        )
        assert "(expected)" in diff
        assert "(actual)" in diff


class TestParseArgs:
    def test_check_flag(self) -> None:
        args = sync_rpm_specs.parse_args(["--check"])
        assert args.check is True

    def test_default_no_check(self) -> None:
        args = sync_rpm_specs.parse_args([])
        assert args.check is False


class TestMain:
    def test_check_mode_in_sync_returns_0(self, tmp_path: Path) -> None:
        expected = sync_rpm_specs.render_local_spec(MIN_OBS_SPEC)
        _setup_spec_tree(tmp_path, MIN_OBS_SPEC, expected)
        with patch.object(sync_rpm_specs, "_repo_root", return_value=tmp_path):
            assert sync_rpm_specs.main(["--check"]) == 0

    def test_check_mode_out_of_sync_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _setup_spec_tree(tmp_path, MIN_OBS_SPEC, "stale\n")
        with patch.object(sync_rpm_specs, "_repo_root", return_value=tmp_path):
            assert sync_rpm_specs.main(["--check"]) == 1
        captured = capsys.readouterr()
        assert "(expected)" in captured.err
        assert "(actual)" in captured.err

    def test_sync_mode_updates_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        expected = sync_rpm_specs.render_local_spec(MIN_OBS_SPEC)
        _setup_spec_tree(tmp_path, MIN_OBS_SPEC, "stale\n")
        with patch.object(sync_rpm_specs, "_repo_root", return_value=tmp_path):
            assert sync_rpm_specs.main([]) == 0
        captured = capsys.readouterr()
        assert "Updated" in captured.out
        local = (
            tmp_path / sync_rpm_specs.LOCAL_SPEC_PATH
        ).read_text(encoding="utf-8")
        assert local == expected

    def test_sync_mode_no_changes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        expected = sync_rpm_specs.render_local_spec(MIN_OBS_SPEC)
        _setup_spec_tree(tmp_path, MIN_OBS_SPEC, expected)
        with patch.object(sync_rpm_specs, "_repo_root", return_value=tmp_path):
            assert sync_rpm_specs.main([]) == 0
        captured = capsys.readouterr()
        assert "No changes" in captured.out


class TestMainModule:
    def test_main_module_exit_code(self) -> None:
        with patch("sys.argv", ["sync_rpm_specs.py", "--check"]):
            try:
                runpy.run_path(str(_script_path), run_name="__main__")
            except SystemExit as exc:
                assert exc.code == 0
                return
        pytest.fail("Expected SystemExit from sys.exit(main())")


def test_sync_rpm_specs_check_mode_succeeds_for_committed_files() -> None:
    """The committed local RPM spec must match generated output."""
    script = repo_root() / "scripts" / "sync_rpm_specs.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--check"],
        cwd=repo_root(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


# REUSE-IgnoreEnd
