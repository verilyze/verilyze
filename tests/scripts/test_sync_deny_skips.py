# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for scripts/sync_deny_skips.py (Renovate deny.toml skip sync)."""

import importlib.util
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.scripts.repo_root import repo_root

_SCRIPT_PATH = repo_root() / "scripts" / "sync_deny_skips.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sync_deny_skips", _SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"Script not found: {_SCRIPT_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _write_deny(tmp_path: Path, skips: list[tuple[str, str]]) -> Path:
    deny = tmp_path / "deny.toml"
    lines = ["[bans]\nskip = [\n"]
    for crate, reason in skips:
        lines.append(f'    {{ crate = "{crate}", reason = "{reason}" }},\n')
    lines.append("]\n")
    deny.write_text("".join(lines), encoding="utf-8")
    return deny


def _write_lock(tmp_path: Path, packages: list[tuple[str, str]]) -> Path:
    lock = tmp_path / "Cargo.lock"
    blocks: list[str] = []
    for name, version in packages:
        blocks.append(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
    lock.write_text("".join(blocks), encoding="utf-8")
    return lock


class TestParseCargoLockVersions:
    def test_collects_multiple_versions_per_crate(self, tmp_path: Path) -> None:
        lock = _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1"), ("syn", "2.0.0")],
        )
        mod = _load_module()
        versions = mod.parse_cargo_lock_versions(lock)
        assert versions["base64"] == ["0.22.1", "0.23.1"]
        assert versions["syn"] == ["2.0.0"]


class TestFindReplacementVersion:
    def test_returns_none_when_pinned_version_still_in_lock(self) -> None:
        mod = _load_module()
        result = mod.find_replacement_version(
            "base64",
            "0.23.1",
            {"base64": ["0.22.1", "0.23.1"]},
        )
        assert result is None

    def test_returns_patch_bump_on_same_major_minor(self) -> None:
        mod = _load_module()
        result = mod.find_replacement_version(
            "base64",
            "0.23.0",
            {"base64": ["0.22.1", "0.23.1"]},
        )
        assert result == "0.23.1"

    def test_updates_only_matching_major_minor_line(self) -> None:
        mod = _load_module()
        result = mod.find_replacement_version(
            "windows-sys",
            "0.45.0",
            {"windows-sys": ["0.45.1", "0.52.0"]},
        )
        assert result == "0.45.1"

    def test_leaves_other_windows_sys_skip_untouched(self, tmp_path: Path) -> None:
        deny = _write_deny(
            tmp_path,
            [
                ("windows-sys@0.45.0", "legacy jni"),
                ("windows-sys@0.52.0", "crypto stack"),
            ],
        )
        lock = _write_lock(
            tmp_path,
            [("windows-sys", "0.45.1"), ("windows-sys", "0.52.0")],
        )
        mod = _load_module()
        changed = mod.sync_deny_skips(deny, lock)
        assert changed is True
        text = deny.read_text(encoding="utf-8")
        assert "windows-sys@0.45.1" in text
        assert "windows-sys@0.52.0" in text
        assert "windows-sys@0.45.0" not in text

    def test_raises_when_crate_missing_from_lock(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="missing from Cargo.lock"):
            mod.find_replacement_version("missing-crate", "1.0.0", {})

    def test_raises_when_no_same_major_minor_candidate(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="no lock version"):
            mod.find_replacement_version(
                "base64",
                "0.23.0",
                {"base64": ["0.22.1", "0.24.0"]},
            )

    def test_raises_when_multiple_same_major_minor_candidates(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="ambiguous"):
            mod.find_replacement_version(
                "example",
                "1.0.0",
                {"example": ["1.0.1", "1.0.2"]},
            )


class TestSyncDenySkips:
    def test_no_change_when_already_aligned(self, tmp_path: Path) -> None:
        deny = _write_deny(
            tmp_path,
            [("base64@0.23.1", "sonatype direct dep")],
        )
        lock = _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1")],
        )
        mod = _load_module()
        changed = mod.sync_deny_skips(deny, lock)
        assert changed is False
        assert 'base64@0.23.1' in deny.read_text(encoding="utf-8")

    def test_updates_stale_patch_pin(self, tmp_path: Path) -> None:
        deny = _write_deny(
            tmp_path,
            [("base64@0.23.0", "sonatype direct dep")],
        )
        lock = _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1")],
        )
        mod = _load_module()
        changed = mod.sync_deny_skips(deny, lock)
        assert changed is True
        assert 'base64@0.23.1' in deny.read_text(encoding="utf-8")
        assert "base64@0.23.0" not in deny.read_text(encoding="utf-8")

    def test_check_mode_reports_drift_without_writing(self, tmp_path: Path) -> None:
        deny = _write_deny(
            tmp_path,
            [("base64@0.23.0", "sonatype direct dep")],
        )
        original = deny.read_text(encoding="utf-8")
        lock = _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1")],
        )
        mod = _load_module()
        drift = mod.sync_deny_skips(deny, lock, check=True)
        assert drift is True
        assert deny.read_text(encoding="utf-8") == original

    def test_repo_deny_skips_match_cargo_lock(self) -> None:
        mod = _load_module()
        root = repo_root()
        assert (
            mod.sync_deny_skips(root / "deny.toml", root / "Cargo.lock", check=True)
            is False
        )


class TestParseSkipSpec:
    def test_rejects_spec_without_at(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="invalid skip crate spec"):
            mod.parse_skip_spec("base64")

    def test_rejects_empty_name_or_version(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="invalid skip crate spec"):
            mod.parse_skip_spec("@0.1.0")


class TestMajorMinor:
    def test_rejects_invalid_semver(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="invalid semver"):
            mod.major_minor("not-a-version")


class TestApplySkipUpdates:
    def test_raises_when_skip_line_missing(self) -> None:
        mod = _load_module()
        with pytest.raises(mod.SyncDenySkipsError, match="missing skip entry"):
            mod.apply_skip_updates(
                '[bans]\nskip = []\n',
                [("base64", "0.23.0", "0.23.1")],
            )


class TestExtractSkipSpecs:
    def test_raises_when_bans_section_missing(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text('[licenses]\nallow = ["MIT"]\n', encoding="utf-8")
        mod = _load_module()
        with pytest.raises(SystemExit, match="missing required key"):
            mod.extract_skip_specs(deny)

    def test_raises_when_skip_not_a_list(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text('[bans]\nskip = "nope"\n', encoding="utf-8")
        mod = _load_module()
        with pytest.raises(SystemExit, match="must be a list"):
            mod.extract_skip_specs(deny)

    def test_raises_when_entry_missing_crate(self, tmp_path: Path) -> None:
        deny = tmp_path / "deny.toml"
        deny.write_text(
            '[bans]\nskip = [\n  { reason = "legacy" },\n]\n',
            encoding="utf-8",
        )
        mod = _load_module()
        with pytest.raises(SystemExit, match="missing crate"):
            mod.extract_skip_specs(deny)


class TestMain:
    def test_main_check_mode_in_sync_returns_0(self, tmp_path: Path) -> None:
        deny = _write_deny(tmp_path, [("base64@0.23.1", "direct dep")])
        _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1")],
        )
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync_deny_skips.py", "--check"]):
                assert mod.main() == 0

    def test_main_check_mode_out_of_sync_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        deny = _write_deny(tmp_path, [("base64@0.23.0", "direct dep")])
        _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1")],
        )
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync_deny_skips.py", "--check"]):
                assert mod.main() == 1
        assert "out of sync" in capsys.readouterr().err

    def test_main_sync_prints_update_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        deny = _write_deny(tmp_path, [("base64@0.23.0", "direct dep")])
        _write_lock(
            tmp_path,
            [("base64", "0.22.1"), ("base64", "0.23.1")],
        )
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync_deny_skips.py"]):
                assert mod.main() == 0
        assert "Updated deny.toml" in capsys.readouterr().out

    def test_main_deny_not_found_returns_1(self, tmp_path: Path) -> None:
        _write_lock(tmp_path, [("base64", "0.23.1")])
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync_deny_skips.py"]):
                assert mod.main() == 1

    def test_main_lock_not_found_returns_1(self, tmp_path: Path) -> None:
        _write_deny(tmp_path, [("base64@0.23.1", "direct dep")])
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync_deny_skips.py"]):
                assert mod.main() == 1

    def test_main_sync_error_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        deny = _write_deny(tmp_path, [("missing-crate@1.0.0", "legacy")])
        _write_lock(tmp_path, [("base64", "0.23.1")])
        mod = _load_module()
        with patch.object(mod, "get_repo_root", return_value=tmp_path):
            with patch("sys.argv", ["sync_deny_skips.py"]):
                assert mod.main() == 1
        assert "missing from Cargo.lock" in capsys.readouterr().err


class TestScriptMain:
    def test_script_main_block_executes(self) -> None:
        root = repo_root()
        if not (root / "deny.toml").exists() or not (root / "Cargo.lock").exists():
            pytest.skip("deny.toml or Cargo.lock not in repo root")
        orig_argv = sys.argv
        try:
            sys.argv = [str(_SCRIPT_PATH.name)]
            runpy.run_path(str(_SCRIPT_PATH), run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 0
        finally:
            sys.argv = orig_argv
