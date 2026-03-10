# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/generate_packaging_versions.py (NFR-012)."""

import importlib.util
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest

# Load generate_packaging_versions module
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "scripts"
    / "generate_packaging_versions.py"
)
_spec = importlib.util.spec_from_file_location(
    "generate_packaging_versions", _script_path
)
generate_packaging_versions = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_packaging_versions)  # type: ignore[union-attr]


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_parent_of_scripts(self) -> None:
        root = generate_packaging_versions.get_repo_root()
        assert (root / "scripts" / "generate_packaging_versions.py").exists()
        assert root.name != "scripts"


class TestGetVersion:
    """Tests for get_version."""

    def test_extracts_version_from_cargo_toml(self, tmp_path: Path) -> None:
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[workspace.package]\nversion = "1.2.3"\n',
            encoding="utf-8",
        )
        result = generate_packaging_versions.get_version(cargo)
        assert result == "1.2.3"

    def test_raises_system_exit_on_missing_workspace(self, tmp_path: Path) -> None:
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[package]\nversion = "1.0.0"\n', encoding="utf-8")
        with pytest.raises(SystemExit):
            generate_packaging_versions.get_version(cargo)

    def test_raises_system_exit_on_missing_version_key(self, tmp_path: Path) -> None:
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[workspace.package]\nname = "vlz"\n',
            encoding="utf-8",
        )
        with pytest.raises(SystemExit):
            generate_packaging_versions.get_version(cargo)

    def test_raises_system_exit_on_type_error(self, tmp_path: Path) -> None:
        """package as non-dict causes TypeError when accessing version."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[workspace]\npackage = 1\n',
            encoding="utf-8",
        )
        with pytest.raises(SystemExit):
            generate_packaging_versions.get_version(cargo)


class TestUpdateApkbuild:
    """Tests for update_apkbuild."""

    def test_replaces_pkgver_line(self) -> None:
        content = "pkgname=verilyze\npkgver=0.1.0\npkgrel=0\n"
        result = generate_packaging_versions.update_apkbuild(content, "2.0.0")
        assert "pkgver=2.0.0" in result
        assert "pkgver=0.1.0" not in result

    def test_replaces_only_first_pkgver(self) -> None:
        content = "pkgver=0.1.0\n# pkgver in comment\npkgver=0.2.0\n"
        result = generate_packaging_versions.update_apkbuild(content, "1.0.0")
        assert result.count("pkgver=1.0.0") == 1


class TestUpdatePkgbuild:
    """Tests for update_pkgbuild."""

    def test_replaces_pkgver_line(self) -> None:
        content = "pkgname=verilyze\npkgver=0.1.0\npkgrel=1\n"
        result = generate_packaging_versions.update_pkgbuild(content, "3.0.0")
        assert "pkgver=3.0.0" in result
        assert "pkgver=0.1.0" not in result

    def test_replaces_only_first_pkgver(self) -> None:
        content = "pkgver=0.1.0\npkgver=0.2.0\n"
        result = generate_packaging_versions.update_pkgbuild(content, "1.0.0")
        assert result.count("pkgver=1.0.0") == 1


class TestMain:
    """Tests for main."""

    def _setup_fixture(
        self,
        tmp_path: Path,
        version: str = "0.5.0",
        apk_ver: str | None = None,
        pkg_ver: str | None = None,
    ) -> None:
        """Create Cargo.toml and packaging files."""
        if apk_ver is None:
            apk_ver = version
        if pkg_ver is None:
            pkg_ver = version
        (tmp_path / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{version}"\n',
            encoding="utf-8",
        )
        (tmp_path / "packaging" / "alpine").mkdir(parents=True)
        (tmp_path / "packaging" / "arch").mkdir(parents=True)
        (tmp_path / "packaging" / "alpine" / "APKBUILD").write_text(
            f"pkgname=verilyze\npkgver={apk_ver}\npkgrel=0\n",
            encoding="utf-8",
        )
        (tmp_path / "packaging" / "arch" / "PKGBUILD").write_text(
            f"pkgname=verilyze\npkgver={pkg_ver}\npkgrel=1\n",
            encoding="utf-8",
        )

    def test_cargo_toml_not_found_returns_1(self, tmp_path: Path) -> None:
        (tmp_path / "packaging" / "alpine").mkdir(parents=True)
        (tmp_path / "packaging" / "arch").mkdir(parents=True)
        (tmp_path / "packaging" / "alpine" / "APKBUILD").write_text(
            "pkgver=0.1.0\n", encoding="utf-8"
        )
        (tmp_path / "packaging" / "arch" / "PKGBUILD").write_text(
            "pkgver=0.1.0\n", encoding="utf-8"
        )
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 1

    def test_apkbuild_not_found_returns_1(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        (tmp_path / "packaging" / "alpine" / "APKBUILD").unlink()
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 1

    def test_pkgbuild_not_found_returns_1(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        (tmp_path / "packaging" / "arch" / "PKGBUILD").unlink()
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 1

    def test_check_mode_in_sync_returns_0(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py", "--check"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 0

    def test_check_mode_apkbuild_out_of_sync_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._setup_fixture(tmp_path, version="1.0.0", apk_ver="0.1.0")
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py", "--check"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "out of sync" in captured.err
        assert "generate-packaging" in captured.err

    def test_check_mode_pkgbuild_out_of_sync_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._setup_fixture(tmp_path, version="1.0.0", pkg_ver="0.1.0")
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py", "--check"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "out of sync" in captured.err

    def test_default_mode_writes_updated_files(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path, version="2.3.4", apk_ver="0.1.0", pkg_ver="0.1.0")
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 0
        apk = (tmp_path / "packaging" / "alpine" / "APKBUILD").read_text()
        pkg = (tmp_path / "packaging" / "arch" / "PKGBUILD").read_text()
        assert "pkgver=2.3.4" in apk
        assert "pkgver=2.3.4" in pkg

    def test_default_mode_preserves_other_content(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        apk_content = "pkgname=verilyze\npkgver=0.1.0\npkgrel=0\npkgdesc=test\n"
        (tmp_path / "packaging" / "alpine" / "APKBUILD").write_text(
            apk_content, encoding="utf-8"
        )
        with patch.object(
            generate_packaging_versions,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_packaging_versions.main()
        assert exit_code == 0
        result = (tmp_path / "packaging" / "alpine" / "APKBUILD").read_text()
        assert "pkgver=0.5.0" in result
        assert "pkgdesc=test" in result


class TestMainModule:
    """Tests for __main__ execution."""

    def test_main_module_exit_code(self) -> None:
        """Running as __main__ invokes main() and exits with its return code."""
        script = (
            Path(__file__).resolve().parent.parent.parent
            / "scripts"
            / "generate_packaging_versions.py"
        )
        with patch("sys.argv", ["gen.py", "--check"]):
            try:
                runpy.run_path(str(script), run_name="__main__")
            except SystemExit as e:
                assert e.code == 0
                return
        pytest.fail("Expected SystemExit from sys.exit(main())")


# REUSE-IgnoreEnd
