# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for scripts/renovate_rust_constraint.py."""

import json
import sys
from pathlib import Path

import pytest

from scripts.renovate_rust_constraint import (
    RENOVATE_JSON_REL,
    RUST_TOOLCHAIN_REL,
    get_repo_root,
    main,
    parse_rust_toolchain_channel,
    read_renovate_rust_constraint,
    sync_renovate_rust_constraint,
    write_renovate_rust_constraint,
)
from tests.scripts.repo_root import repo_root

_ROOT = repo_root()

_TOOLCHAIN_FIXTURE = """\
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

[toolchain]
channel = "1.99.0"
components = ["rustfmt", "clippy", "llvm-tools"]
"""

_RENOVATE_FIXTURE = {
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "constraints": {"rust": "1.94.1"},
    "packageRules": [],
}


class TestParseRustToolchainChannel:
    def test_parse_channel_from_toolchain_toml(self) -> None:
        assert parse_rust_toolchain_channel(_TOOLCHAIN_FIXTURE) == "1.99.0"

    def test_parse_channel_missing_raises(self) -> None:
        with pytest.raises(SystemExit, match="channel"):
            parse_rust_toolchain_channel("[toolchain]\ncomponents = []\n")


class TestRenovateConstraintRoundTrip:
    def test_read_renovate_rust_constraint(self, tmp_path: Path) -> None:
        path = tmp_path / "renovate.json"
        path.write_text(json.dumps(_RENOVATE_FIXTURE), encoding="utf-8")
        assert read_renovate_rust_constraint(path) == "1.94.1"

    def test_read_missing_constraints_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "renovate.json"
        path.write_text("{}", encoding="utf-8")
        with pytest.raises(SystemExit, match="constraints.rust"):
            read_renovate_rust_constraint(path)

    def test_read_empty_rust_constraint_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "renovate.json"
        path.write_text(
            json.dumps({"constraints": {"rust": ""}}), encoding="utf-8"
        )
        with pytest.raises(SystemExit, match="constraints.rust"):
            read_renovate_rust_constraint(path)

    def test_write_missing_constraints_object_raises(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "renovate.json"
        path.write_text("{}", encoding="utf-8")
        with pytest.raises(SystemExit, match="constraints object"):
            write_renovate_rust_constraint(path, "1.99.0")

    def test_write_renovate_rust_constraint_updates_value(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "renovate.json"
        path.write_text(
            json.dumps(_RENOVATE_FIXTURE, indent=2), encoding="utf-8"
        )
        changed = write_renovate_rust_constraint(path, "1.99.0")
        assert changed is True
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["constraints"]["rust"] == "1.99.0"

    def test_write_noop_when_already_aligned(self, tmp_path: Path) -> None:
        path = tmp_path / "renovate.json"
        data = dict(_RENOVATE_FIXTURE)
        data["constraints"] = {"rust": "1.99.0"}
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        before = path.read_text(encoding="utf-8")
        changed = write_renovate_rust_constraint(path, "1.99.0")
        assert changed is False
        assert path.read_text(encoding="utf-8") == before


class TestSyncRenovateRustConstraint:
    def _seed_repo(self, tmp_path: Path, *, constraint: str) -> Path:
        (tmp_path / RUST_TOOLCHAIN_REL).write_text(
            _TOOLCHAIN_FIXTURE, encoding="utf-8"
        )
        renovate = dict(_RENOVATE_FIXTURE)
        renovate["constraints"] = {"rust": constraint}
        (tmp_path / RENOVATE_JSON_REL).write_text(
            json.dumps(renovate, indent=2) + "\n", encoding="utf-8"
        )
        return tmp_path

    def test_sync_writes_when_drifted(self, tmp_path: Path) -> None:
        root = self._seed_repo(tmp_path, constraint="1.94.1")
        changed = sync_renovate_rust_constraint(root, check=False)
        assert changed is True
        assert (
            read_renovate_rust_constraint(root / RENOVATE_JSON_REL) == "1.99.0"
        )

    def test_sync_check_reports_drift_without_write(
        self, tmp_path: Path
    ) -> None:
        root = self._seed_repo(tmp_path, constraint="1.94.1")
        before = (root / RENOVATE_JSON_REL).read_text(encoding="utf-8")
        changed = sync_renovate_rust_constraint(root, check=True)
        assert changed is True
        assert (root / RENOVATE_JSON_REL).read_text(encoding="utf-8") == before

    def test_sync_aligned_is_noop(self, tmp_path: Path) -> None:
        root = self._seed_repo(tmp_path, constraint="1.99.0")
        assert sync_renovate_rust_constraint(root, check=False) is False
        assert sync_renovate_rust_constraint(root, check=True) is False


class TestMainCli:
    def test_main_check_fails_on_drift(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = TestSyncRenovateRustConstraint()._seed_repo(
            tmp_path, constraint="1.94.1"
        )
        monkeypatch.setattr(
            "scripts.renovate_rust_constraint.get_repo_root", lambda: root
        )
        monkeypatch.setattr(
            sys, "argv", ["renovate_rust_constraint.py", "--check"]
        )
        assert main() == 1
        err = capsys.readouterr().err
        assert "constraints.rust" in err
        assert "1.99.0" in err

    def test_main_write_aligns_constraint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = TestSyncRenovateRustConstraint()._seed_repo(
            tmp_path, constraint="1.94.1"
        )
        monkeypatch.setattr(
            "scripts.renovate_rust_constraint.get_repo_root", lambda: root
        )
        monkeypatch.setattr(sys, "argv", ["renovate_rust_constraint.py"])
        assert main() == 0
        assert (
            read_renovate_rust_constraint(root / RENOVATE_JSON_REL) == "1.99.0"
        )

    def test_main_check_passes_when_aligned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = TestSyncRenovateRustConstraint()._seed_repo(
            tmp_path, constraint="1.99.0"
        )
        monkeypatch.setattr(
            "scripts.renovate_rust_constraint.get_repo_root", lambda: root
        )
        monkeypatch.setattr(
            sys, "argv", ["renovate_rust_constraint.py", "--check"]
        )
        assert main() == 0


def test_get_repo_root_points_at_workspace() -> None:
    assert get_repo_root() == _ROOT
    assert (get_repo_root() / RUST_TOOLCHAIN_REL).is_file()
    assert (get_repo_root() / RENOVATE_JSON_REL).is_file()
