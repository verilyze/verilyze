# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/sync_license_config.py (TDD, license config sync)."""

import importlib.util
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest

# Load sync_license_config module (may not exist yet during TDD)
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "scripts"
    / "sync_license_config.py"
)


def _load_module():
    """Load sync_license_config module; raises if file does not exist."""
    _spec = importlib.util.spec_from_file_location(
        "sync_license_config", _script_path
    )
    if _spec is None or _spec.loader is None:
        raise FileNotFoundError(f"Script not found: {_script_path}")
    mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestExtractAllowFromDeny:
    """Tests for extracting [licenses] allow from deny.toml."""

    def test_extracts_allow_list(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = [
    "Apache-2.0",
    "MIT",
]
""",
            encoding="utf-8",
        )
        mod = _load_module()
        result = mod.extract_allow_from_deny(deny)
        assert result == ["Apache-2.0", "MIT"]

    def test_preserves_order(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = [
    "BSD-3-Clause",
    "Apache-2.0",
    "MIT",
]
""",
            encoding="utf-8",
        )
        mod = _load_module()
        result = mod.extract_allow_from_deny(deny)
        assert result == ["BSD-3-Clause", "Apache-2.0", "MIT"]

    def test_raises_on_missing_licenses_section(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text('[bans]\nallow = []\n', encoding="utf-8")
        mod = _load_module()
        with pytest.raises((KeyError, ValueError, SystemExit)):
            mod.extract_allow_from_deny(deny)

    def test_raises_on_missing_allow_key(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
confidence-threshold = 0.8
""",
            encoding="utf-8",
        )
        mod = _load_module()
        with pytest.raises((KeyError, ValueError, SystemExit)):
            mod.extract_allow_from_deny(deny)

    def test_raises_when_allow_is_not_list(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = "Apache-2.0"
""",
            encoding="utf-8",
        )
        mod = _load_module()
        with pytest.raises(ValueError, match="licenses.allow must be a list"):
            mod.extract_allow_from_deny(deny)


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_parent_of_scripts_dir(self) -> None:
        mod = _load_module()
        root = mod.get_repo_root()
        assert root.is_dir()
        assert (root / "scripts" / "sync_license_config.py").exists()


class TestUpdateAboutAccepted:
    """Tests for updating accepted in about.toml."""

    def test_updates_accepted_preserves_rest(self, tmp_path: Path) -> None:
        about = tmp_path / "about.toml"
        about.write_text(
            """accepted = ["Old", "List"]
ignore-dev-dependencies = true
workarounds = ["ring", "rustls"]
""",
            encoding="utf-8",
        )
        mod = _load_module()
        changed = mod.update_about_accepted(about, ["Apache-2.0", "MIT"])
        assert changed is True
        content = about.read_text()
        assert "Apache-2.0" in content
        assert "MIT" in content
        assert "Old" not in content
        assert "List" not in content
        assert "ignore-dev-dependencies = true" in content
        assert 'workarounds = ["ring", "rustls"]' in content

    def test_idempotent_when_already_synced(self, tmp_path: Path) -> None:
        about = tmp_path / "about.toml"
        about.write_text(
            """accepted = [
    "Apache-2.0",
    "MIT",
]
workarounds = ["ring"]
""",
            encoding="utf-8",
        )
        mod = _load_module()
        changed_first = mod.update_about_accepted(about, ["Apache-2.0", "MIT"])
        content_after_first = about.read_text()
        changed_second = mod.update_about_accepted(about, ["Apache-2.0", "MIT"])
        content_after_second = about.read_text()
        assert changed_first is True or changed_second is False
        assert content_after_first == content_after_second

    def test_handles_invalid_toml_by_replacing_accepted(self, tmp_path: Path) -> None:
        about = tmp_path / "about.toml"
        about.write_text(
            'accepted = ["Old"]\nkey = "unclosed string',
            encoding="utf-8",
        )
        mod = _load_module()
        changed = mod.update_about_accepted(about, ["MIT"])
        assert changed is True
        assert "MIT" in about.read_text()

    def test_raises_when_no_accepted_block(self, tmp_path: Path) -> None:
        about = tmp_path / "about.toml"
        about.write_text(
            """workarounds = ["ring"]
private = { ignore = true }
""",
            encoding="utf-8",
        )
        mod = _load_module()
        with pytest.raises(SystemExit):
            mod.update_about_accepted(about, ["MIT"])


class TestSyncLicenseConfig:
    """Tests for sync_license_config function."""

    def test_sync_updates_about_from_deny(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = ["ISC", "MIT"]
""",
            encoding="utf-8",
        )
        about = tmp_path / "about.toml"
        about.write_text(
            """accepted = ["Old"]
private = { ignore = true }
""",
            encoding="utf-8",
        )
        mod = _load_module()
        changed = mod.sync_license_config(deny, about)
        assert changed is True
        content = about.read_text()
        assert "ISC" in content
        assert "MIT" in content
        assert "Old" not in content
        assert "private = { ignore = true }" in content

    def test_sync_returns_false_when_no_change(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = ["MIT"]
""",
            encoding="utf-8",
        )
        about = tmp_path / "about.toml"
        about.write_text(
            """accepted = ["MIT"]
""",
            encoding="utf-8",
        )
        mod = _load_module()
        changed = mod.update_about_accepted(about, ["MIT"])
        assert changed is False


class TestMain:
    """Tests for main entry point."""

    def test_main_syncs_when_out_of_sync(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = ["Apache-2.0", "MIT"]
""",
            encoding="utf-8",
        )
        about = tmp_path / "about.toml"
        about.write_text('accepted = ["X"]\n', encoding="utf-8")
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync.py"]):
                exit_code = mod.main()
        assert exit_code == 0
        assert "Apache-2.0" in about.read_text()

    def test_main_check_mode_in_sync_returns_0(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = ["MIT"]
""",
            encoding="utf-8",
        )
        about = tmp_path / "about.toml"
        about.write_text('accepted = ["MIT"]\n', encoding="utf-8")
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync.py", "--check"]):
                exit_code = mod.main()
        assert exit_code == 0

    def test_main_check_mode_out_of_sync_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            """[licenses]
allow = ["Apache-2.0", "MIT"]
""",
            encoding="utf-8",
        )
        about = tmp_path / "about.toml"
        about.write_text('accepted = ["Old"]\n', encoding="utf-8")
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync.py", "--check"]):
                exit_code = mod.main()
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "out of sync" in captured.err or "sync" in captured.err.lower()

    def test_main_deny_not_found_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "about.toml").write_text('accepted = []\n', encoding="utf-8")
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync.py"]):
                exit_code = mod.main()
        assert exit_code == 1

    def test_main_about_not_found_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "deny.toml").write_text(
            """[licenses]
allow = ["MIT"]
""",
            encoding="utf-8",
        )
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync.py"]):
                exit_code = mod.main()
        assert exit_code == 1


class TestScriptMain:
    """Tests for __main__ entry point."""

    def test_script_main_block_executes(self) -> None:
        """Run script via runpy to cover if __name__ == '__main__' block."""
        repo_root = _script_path.resolve().parent.parent
        about_real = repo_root / "about.toml"
        deny_real = repo_root / "deny.toml"
        if not deny_real.exists() or not about_real.exists():
            pytest.skip("deny.toml or about.toml not in repo root")
        saved = about_real.read_text(encoding="utf-8")
        import sys

        orig_argv = sys.argv
        try:
            sys.argv = [str(_script_path.name)]
            runpy.run_path(str(_script_path), run_name="__main__")
        except SystemExit as e:
            assert e.code == 0, f"script exited with {e.code}"
        finally:
            sys.argv = orig_argv
            about_real.write_text(saved, encoding="utf-8")


class TestScriptExists:
    """Smoke test: script file exists (for TDD red phase)."""

    def test_script_file_exists(self) -> None:
        assert _script_path.exists(), (
            f"TDD: Create {_script_path} and implement sync_license_config"
        )


# REUSE-IgnoreEnd
