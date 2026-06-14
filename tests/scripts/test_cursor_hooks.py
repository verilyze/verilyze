# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for Cursor hook validation (scripts/cursor_validation.py)."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cursor-hooks"
_SCRIPT = _ROOT / "scripts" / "cursor_validation.py"
_HOOK_INPUT = _ROOT / "scripts" / "lib" / "cursor-hook-input.sh"
_RUST_FMT_HOOK = _ROOT / ".cursor" / "hooks" / "rust-fmt.sh"
_STOP_HOOK = _ROOT / ".cursor" / "hooks" / "stop-check-followup.sh"

_spec = importlib.util.spec_from_file_location("cursor_validation", _SCRIPT)
cursor_validation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cursor_validation)  # type: ignore[union-attr]


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


class TestParseEditedPaths:
    def test_rust_write_fixture(self) -> None:
        data = _fixture("after_file_edit_rust.json")
        paths = cursor_validation.parse_edited_paths(data)
        assert paths == ["crates/core/vlz/src/main.rs"]

    def test_yaml_write_fixture(self) -> None:
        data = _fixture("after_file_edit_yaml.json")
        paths = cursor_validation.parse_edited_paths(data)
        assert paths == [".github/workflows/ci.yml"]


class TestClassifyChangedPaths:
    def test_rust_only(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["crates/core/vlz/src/lib.rs"]
        )
        assert "make fmt-check clippy" in targets
        assert "make cargo-test" in targets

    def test_python_scripts(self) -> None:
        targets = cursor_validation.classify_changed_paths(["scripts/foo.py"])
        assert targets == ["make lint-python test-scripts"]

    def test_super_linter_yaml(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            [".github/workflows/ci.yml"]
        )
        assert targets == ["make super-linter"]

    def test_workflow_and_rust(self) -> None:
        paths = ["crates/core/vlz/src/lib.rs", ".github/workflows/ci.yml"]
        targets = cursor_validation.classify_changed_paths(paths)
        assert "make super-linter" in targets
        assert "make fmt-check clippy" in targets

    def test_packaging_env_triggers_super_linter(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["packaging/obs/obs-project.env"]
        )
        assert "make check-packaging" in targets
        assert "make super-linter" in targets

    def test_packaging_dockerfile_triggers_super_linter(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["packaging/docker/Dockerfile"]
        )
        assert "make super-linter" in targets


class TestSessionEditPaths:
    def test_clear_read_append(self, tmp_path: Path) -> None:
        paths_file = tmp_path / ".cursor" / ".agent-edited-paths"
        cursor_validation.clear_session_edit_paths(tmp_path, paths_file=paths_file)
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=paths_file
        ) == []

        cursor_validation.append_session_edit_paths(
            tmp_path,
            ["scripts/a.py", "./scripts/b.py"],
            paths_file=paths_file,
        )
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=paths_file
        ) == ["scripts/a.py", "scripts/b.py"]

        cursor_validation.append_session_edit_paths(
            tmp_path,
            ["scripts/a.py", "scripts/c.py"],
            paths_file=paths_file,
        )
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=paths_file
        ) == ["scripts/a.py", "scripts/b.py", "scripts/c.py"]

        cursor_validation.clear_session_edit_paths(tmp_path, paths_file=paths_file)
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=paths_file
        ) == []


class TestShouldEmitFollowup:
    def test_no_session_edits(self) -> None:
        assert (
            cursor_validation.should_emit_followup(
                {},
                session_paths=[],
                diff_paths=["scripts/foo.py"],
                targets=["make lint-python test-scripts"],
            )
            is False
        )

    def test_aborted_status(self) -> None:
        data = {"status": "aborted"}
        assert (
            cursor_validation.should_emit_followup(
                data,
                session_paths=["scripts/foo.py"],
                diff_paths=["scripts/foo.py"],
                targets=["make lint-python test-scripts"],
            )
            is False
        )

    def test_empty_targets(self) -> None:
        assert (
            cursor_validation.should_emit_followup(
                {},
                session_paths=["README.md"],
                diff_paths=["README.md"],
                targets=[],
            )
            is False
        )

    def test_stale_git_diff_without_session_edits(self) -> None:
        assert (
            cursor_validation.should_emit_followup(
                {},
                session_paths=[],
                diff_paths=["tests/scripts/test_sync_obs_project_meta.py"],
                targets=["make lint-python test-scripts"],
            )
            is False
        )

    def test_session_edits_need_scoped_checks(self) -> None:
        targets = ["make lint-python test-scripts"]
        assert (
            cursor_validation.should_emit_followup(
                {},
                session_paths=["scripts/foo.py"],
                diff_paths=["scripts/foo.py"],
                targets=targets,
            )
            is True
        )

    def test_skip_when_checks_already_ran(self) -> None:
        data = _fixture("stop_skip_followup.json")
        targets = ["make lint-python test-scripts"]
        assert (
            cursor_validation.should_emit_followup(
                data,
                session_paths=["scripts/foo.py"],
                diff_paths=["scripts/foo.py"],
                targets=targets,
            )
            is False
        )


class TestFollowupMessage:
    def test_python_scripts_message_scoped_only(self) -> None:
        targets = cursor_validation.classify_changed_paths(["scripts/foo.py"])
        msg = cursor_validation.build_followup_message(targets)
        assert msg == "Run: make lint-python test-scripts."
        assert "check-fast" not in msg

    def test_empty_targets_returns_empty(self) -> None:
        assert cursor_validation.build_followup_message([]) == ""

    def test_unclassified_paths_returns_empty(self) -> None:
        assert cursor_validation.build_followup_message([], ["README.md"]) == ""

    def test_skip_when_last_history_matches(self) -> None:
        data = _fixture("stop_skip_followup.json")
        targets = ["make lint-python test-scripts"]
        assert cursor_validation.should_skip_followup(data, targets) is True

    def test_no_skip_when_target_only_in_earlier_history(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "make lint-python test-scripts",
                    "git status",
                ]
            }
        }
        targets = ["make lint-python test-scripts"]
        assert cursor_validation.should_skip_followup(data, targets) is False

    def test_no_skip_when_last_command_failed(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make super-linter"],
                "last_shell_command_results": [{"exit_code": 1}],
            }
        }
        targets = ["make super-linter"]
        assert cursor_validation.should_skip_followup(data, targets) is False


class TestHooksDisabled:
    def test_disabled_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VLZ_CURSOR_HOOKS_DISABLE", "1")
        assert cursor_validation.hooks_disabled() is True

    def test_enabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VLZ_CURSOR_HOOKS_DISABLE", raising=False)
        assert cursor_validation.hooks_disabled() is False


@pytest.mark.skipif(
    not _RUST_FMT_HOOK.is_file(), reason="hook not installed yet"
)
class TestRustFmtHookScoping:
    def test_formats_only_listed_rust_files(self, tmp_path: Path) -> None:
        """rustfmt on one file must not rewrite unrelated .rs files."""
        if not shutil.which("rustfmt"):
            pytest.skip("rustfmt not installed")
        untouched = tmp_path / "untouched.rs"
        touched = tmp_path / "touched.rs"
        untouched.write_text("fn main(){}\n", encoding="utf-8")
        touched.write_text("fn main(){}\n", encoding="utf-8")
        before_untouched = untouched.read_text(encoding="utf-8")

        proc = subprocess.run(
            ["rustfmt", str(touched)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert untouched.read_text(encoding="utf-8") == before_untouched

    def test_rust_fmt_hook_noops_on_yaml_fixture(self) -> None:
        fixture = (_FIXTURES / "after_file_edit_yaml.json").read_text(
            encoding="utf-8"
        )
        proc = subprocess.run(
            [str(_RUST_FMT_HOOK)],
            input=fixture,
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout


class TestHookScriptsExist:
    def test_lib_and_hooks_present_after_install(self) -> None:
        _SESSION_TRACK = _ROOT / ".cursor" / "hooks" / "session-track-edits.sh"
        assert _SCRIPT.is_file()
        assert _HOOK_INPUT.is_file()
        assert _RUST_FMT_HOOK.is_file()
        assert _STOP_HOOK.is_file()
        assert _SESSION_TRACK.is_file()
        assert (_ROOT / ".cursor" / "hooks.json").is_file()
