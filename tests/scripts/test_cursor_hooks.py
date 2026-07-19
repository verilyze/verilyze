# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for Cursor hook validation (scripts/cursor_validation.py)."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
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

    def test_edits_and_files_lists(self) -> None:
        data = {
            "edits": [{"path": "scripts/a.py"}],
            "files": ["scripts/b.py"],
        }
        paths = cursor_validation.parse_edited_paths(data)
        assert paths == ["scripts/a.py", "scripts/b.py"]


class TestCollectChangedPaths:
    def test_git_output_returns_stdout_on_success(self, tmp_path: Path) -> None:
        from unittest.mock import MagicMock

        proc = MagicMock(returncode=0, stdout="ok\n")
        with patch("scripts.cursor_validation.subprocess.run", return_value=proc):
            assert cursor_validation._git_output(tmp_path, "status") == "ok\n"

    def test_git_output_returns_empty_on_failure(self, tmp_path: Path) -> None:
        from unittest.mock import MagicMock

        proc = MagicMock(returncode=1, stdout="")
        with patch("scripts.cursor_validation.subprocess.run", return_value=proc):
            assert cursor_validation._git_output(tmp_path, "status") == ""

    def test_collects_git_diff_paths(self, tmp_path: Path, monkeypatch) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()

        def fake_git_output(_root: Path, *args: str) -> str:
            if args == ("diff", "--name-only"):
                return "scripts/new.py\n"
            if args == ("merge-base", "origin/main", "HEAD"):
                return "abc\n"
            if args == ("diff", "--name-only", "abc..HEAD"):
                return "crates/foo.rs\n"
            return ""

        monkeypatch.setattr(
            cursor_validation, "_git_output", fake_git_output
        )
        paths = cursor_validation.collect_changed_paths(repo)
        assert paths == ["scripts/new.py", "crates/foo.rs"]


class TestRustPaths:
    def test_filters_rust_only(self) -> None:
        assert cursor_validation.rust_paths(
            ["crates/a.rs", "scripts/b.py"]
        ) == ["crates/a.rs"]


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

    def test_shell_scripts_trigger_lint_shell(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["scripts/foo.sh"]
        )
        assert targets == ["make lint-shell"]

    def test_architecture_mmd_triggers_doc_diagrams(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["architecture/flow.mmd"]
        )
        assert targets == ["make check-doc-diagrams"]

    def test_man_pages_trigger_config_and_manpage_checks(self) -> None:
        targets = cursor_validation.classify_changed_paths(["man/vlz.1"])
        assert "make check-config-docs" in targets
        assert "make check-manpages" in targets

    def test_cargo_toml_triggers_dependency_gates(self) -> None:
        targets = cursor_validation.classify_changed_paths(["Cargo.toml"])
        assert "make cargo-check-locked" in targets
        assert "make deny-check" in targets
        assert "make check-third-party-licenses" in targets
        assert "make check-sbom" in targets

    def test_cargo_lock_triggers_dependency_gates(self) -> None:
        targets = cursor_validation.classify_changed_paths(["Cargo.lock"])
        assert "make cargo-check-locked" in targets
        assert "make deny-check" in targets
        assert "make check-third-party-licenses" in targets
        assert "make check-sbom" in targets

    def test_deny_toml_triggers_policy_gates(self) -> None:
        targets = cursor_validation.classify_changed_paths(["deny.toml"])
        assert targets == [
            "make deny-check",
            "make check-third-party-licenses",
        ]

    def test_pyproject_triggers_check_sbom(self) -> None:
        targets = cursor_validation.classify_changed_paths(["pyproject.toml"])
        assert targets == ["make check-sbom"]


class TestNeedsSuperLinter:
    def test_true_for_biome_json(self) -> None:
        assert cursor_validation.needs_super_linter(["biome.json"]) is True

    def test_false_for_readme(self) -> None:
        assert cursor_validation.needs_super_linter(["README.md"]) is False

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

    def test_write_empty_paths_unlinks_file(self, tmp_path: Path) -> None:
        paths_file = tmp_path / "paths.txt"
        paths_file.write_text("scripts/a.py\n", encoding="utf-8")
        cursor_validation.write_session_edit_paths(
            tmp_path, [], paths_file=paths_file
        )
        assert not paths_file.exists()

    def test_custom_paths_file_override(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom-paths.txt"
        assert cursor_validation.session_edit_paths_file(
            tmp_path, paths_file=custom
        ) == custom

    def test_default_session_paths_file(self, tmp_path: Path) -> None:
        assert cursor_validation.session_edit_paths_file(tmp_path) == (
            tmp_path / ".cursor" / ".agent-edited-paths"
        )

    def test_read_session_uses_custom_paths_file(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom-paths.txt"
        custom.write_text("scripts/z.py\n", encoding="utf-8")
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=custom
        ) == ["scripts/z.py"]


class TestTurnEditPaths:
    def test_clear_read_append(self, tmp_path: Path) -> None:
        turn_file = tmp_path / ".cursor" / ".agent-turn-paths"
        cursor_validation.clear_turn_edit_paths(tmp_path, paths_file=turn_file)
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == []

        cursor_validation.append_turn_edit_paths(
            tmp_path,
            ["crates/a.rs"],
            paths_file=turn_file,
        )
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == ["crates/a.rs"]

        cursor_validation.clear_turn_edit_paths(tmp_path, paths_file=turn_file)
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == []

    def test_append_agent_edit_paths_updates_both(self, tmp_path: Path) -> None:
        pending_file = tmp_path / ".cursor" / ".agent-edited-paths"
        turn_file = tmp_path / ".cursor" / ".agent-turn-paths"
        cursor_validation.append_agent_edit_paths(
            tmp_path,
            ["scripts/a.py"],
            paths_file=pending_file,
            turn_paths_file=turn_file,
        )
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=pending_file
        ) == ["scripts/a.py"]
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == ["scripts/a.py"]

    def test_default_turn_paths_file(self, tmp_path: Path) -> None:
        assert cursor_validation.turn_edit_paths_file(tmp_path) == (
            tmp_path / ".cursor" / ".agent-turn-paths"
        )

    def test_clear_agent_edit_paths_clears_both(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.append_agent_edit_paths(
            tmp_path,
            ["scripts/a.py"],
            paths_file=pending_file,
            turn_paths_file=turn_file,
        )
        cursor_validation.clear_agent_edit_paths(
            tmp_path,
            paths_file=pending_file,
            turn_paths_file=turn_file,
        )
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=pending_file
        ) == []
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == []


class TestTargetsSatisfiedByHistory:
    def test_all_targets_in_separate_commands(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "make fmt-check clippy",
                    "make cargo-test",
                ],
                "last_shell_command_results": [
                    {"exit_code": 0},
                    {"exit_code": 0},
                ],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is True

    def test_compound_command_satisfies_both(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "make fmt-check clippy; make cargo-test",
                ],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is True

    def test_false_when_one_target_missing(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make fmt-check clippy"],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is False

    def test_false_when_history_length_mismatch(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make cargo-test"],
                "last_shell_command_results": [],
            }
        }
        assert (
            cursor_validation.targets_satisfied_by_history(
                data, ["make cargo-test"]
            )
            is False
        )

    def test_false_for_empty_targets(self) -> None:
        assert cursor_validation.targets_satisfied_by_history({}, []) is False

    def test_false_when_shell_history_empty(self) -> None:
        data = {"conversation": {"last_shell_commands": []}}
        assert (
            cursor_validation.targets_satisfied_by_history(
                data, ["make cargo-test"]
            )
            is False
        )


class TestLastTargetCommandFailed:
    def test_true_when_last_target_failed(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make cargo-test"],
                "last_shell_command_results": [{"exit_code": 1}],
            }
        }
        assert (
            cursor_validation.last_target_command_failed(
                data, ["make cargo-test"]
            )
            is True
        )

    def test_false_when_last_target_succeeded(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make cargo-test"],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        assert (
            cursor_validation.last_target_command_failed(
                data, ["make cargo-test"]
            )
            is False
        )

    def test_false_for_empty_targets(self) -> None:
        assert cursor_validation.last_target_command_failed({}, []) is False

    def test_false_when_last_command_does_not_match_target(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["git status"],
                "last_shell_command_results": [{"exit_code": 1}],
            }
        }
        assert (
            cursor_validation.last_target_command_failed(
                data, ["make cargo-test"]
            )
            is False
        )


class TestShouldEmitFollowup:
    def test_no_turn_or_pending_edits(self) -> None:
        assert (
            cursor_validation.should_emit_followup(
                {},
                turn_paths=[],
                pending_paths=[],
                targets=["make lint-python test-scripts"],
            )
            is False
        )

    def test_aborted_status(self) -> None:
        data = {"status": "aborted"}
        assert (
            cursor_validation.should_emit_followup(
                data,
                turn_paths=["scripts/foo.py"],
                pending_paths=["scripts/foo.py"],
                targets=["make lint-python test-scripts"],
            )
            is False
        )

    def test_empty_targets(self) -> None:
        assert (
            cursor_validation.should_emit_followup(
                {},
                turn_paths=["README.md"],
                pending_paths=["README.md"],
                targets=[],
            )
            is False
        )

    def test_stale_pending_without_turn_edits(self) -> None:
        assert (
            cursor_validation.should_emit_followup(
                {},
                turn_paths=[],
                pending_paths=["crates/core/vlz/src/lib.rs"],
                targets=["make fmt-check clippy", "make cargo-test"],
            )
            is False
        )

    def test_turn_edits_need_scoped_checks(self) -> None:
        targets = ["make lint-python test-scripts"]
        assert (
            cursor_validation.should_emit_followup(
                {},
                turn_paths=["scripts/foo.py"],
                pending_paths=["scripts/foo.py"],
                targets=targets,
            )
            is True
        )

    def test_retry_when_last_check_failed(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make cargo-test"],
                "last_shell_command_results": [{"exit_code": 1}],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert (
            cursor_validation.should_emit_followup(
                data,
                turn_paths=[],
                pending_paths=["crates/core/vlz/src/lib.rs"],
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
                turn_paths=["scripts/foo.py"],
                pending_paths=["scripts/foo.py"],
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

    def test_skip_when_no_conversation(self) -> None:
        assert (
            cursor_validation.should_skip_followup({}, ["make lint-python test-scripts"])
            is False
        )

    def test_skip_when_history_length_mismatch(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make lint-python test-scripts"],
                "last_shell_command_results": [],
            }
        }
        assert (
            cursor_validation.should_skip_followup(
                data, ["make lint-python test-scripts"]
            )
            is False
        )


class TestResolveStopFollowup:
    def test_returns_message_when_checks_needed(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_session_edit_paths(
            tmp_path,
            ["scripts/foo.py"],
            paths_file=pending_file,
        )
        cursor_validation.write_turn_edit_paths(
            tmp_path,
            ["scripts/foo.py"],
            paths_file=turn_file,
        )
        msg = cursor_validation.resolve_stop_followup(
            {},
            tmp_path,
            paths_file=pending_file,
            turn_paths_file=turn_file,
        )
        assert msg == "Run: make lint-python test-scripts."
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == []

    def test_returns_none_when_aborted(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_session_edit_paths(
            tmp_path,
            ["scripts/foo.py"],
            paths_file=pending_file,
        )
        cursor_validation.write_turn_edit_paths(
            tmp_path,
            ["scripts/foo.py"],
            paths_file=turn_file,
        )
        assert (
            cursor_validation.resolve_stop_followup(
                {"status": "aborted"},
                tmp_path,
                paths_file=pending_file,
                turn_paths_file=turn_file,
            )
            is None
        )

    def test_stale_pending_without_turn_edits(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_session_edit_paths(
            tmp_path,
            ["crates/core/vlz/src/lib.rs"],
            paths_file=pending_file,
        )
        assert (
            cursor_validation.resolve_stop_followup(
                {},
                tmp_path,
                paths_file=pending_file,
                turn_paths_file=turn_file,
            )
            is None
        )

    def test_rust_turn_paths_emit_scoped_targets(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_turn_edit_paths(
            tmp_path,
            ["crates/core/vlz/src/lib.rs"],
            paths_file=turn_file,
        )
        msg = cursor_validation.resolve_stop_followup(
            {},
            tmp_path,
            paths_file=pending_file,
            turn_paths_file=turn_file,
        )
        assert msg == "Run: make fmt-check clippy; make cargo-test."

    def test_clears_pending_when_checks_succeeded(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_session_edit_paths(
            tmp_path,
            ["crates/core/vlz/src/lib.rs"],
            paths_file=pending_file,
        )
        data = {
            "conversation": {
                "last_shell_commands": [
                    "make fmt-check clippy",
                    "make cargo-test",
                ],
                "last_shell_command_results": [
                    {"exit_code": 0},
                    {"exit_code": 0},
                ],
            }
        }
        assert (
            cursor_validation.resolve_stop_followup(
                data,
                tmp_path,
                paths_file=pending_file,
                turn_paths_file=turn_file,
            )
            is None
        )
        assert not pending_file.exists()

    def test_retries_when_last_check_failed(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_session_edit_paths(
            tmp_path,
            ["crates/core/vlz/src/lib.rs"],
            paths_file=pending_file,
        )
        data = {
            "conversation": {
                "last_shell_commands": ["make cargo-test"],
                "last_shell_command_results": [{"exit_code": 1}],
            }
        }
        msg = cursor_validation.resolve_stop_followup(
            data,
            tmp_path,
            paths_file=pending_file,
            turn_paths_file=turn_file,
        )
        assert msg == "Run: make fmt-check clippy; make cargo-test."

    def test_returns_none_for_unclassified_turn_paths(self, tmp_path: Path) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_turn_edit_paths(
            tmp_path,
            ["README.md"],
            paths_file=turn_file,
        )
        assert (
            cursor_validation.resolve_stop_followup(
                {},
                tmp_path,
                paths_file=pending_file,
                turn_paths_file=turn_file,
            )
            is None
        )

    def test_clears_pending_when_turn_checks_already_succeeded(
        self, tmp_path: Path
    ) -> None:
        pending_file = tmp_path / "pending.txt"
        turn_file = tmp_path / "turn.txt"
        cursor_validation.write_session_edit_paths(
            tmp_path,
            ["crates/core/vlz/src/lib.rs"],
            paths_file=pending_file,
        )
        cursor_validation.write_turn_edit_paths(
            tmp_path,
            ["scripts/foo.py"],
            paths_file=turn_file,
        )
        data = _fixture("stop_skip_followup.json")
        assert (
            cursor_validation.resolve_stop_followup(
                data,
                tmp_path,
                paths_file=pending_file,
                turn_paths_file=turn_file,
            )
            is None
        )
        assert not pending_file.exists()


class TestLoadHookJson:
    def test_parses_object(self) -> None:
        data = cursor_validation.load_hook_json('{"status": "completed"}')
        assert data == {"status": "completed"}

    def test_rejects_non_object(self) -> None:
        with pytest.raises(TypeError, match="JSON object"):
            cursor_validation.load_hook_json("[]")


class TestGetRepoRoot:
    def test_points_at_repository_root(self) -> None:
        assert cursor_validation.get_repo_root() == _ROOT


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
