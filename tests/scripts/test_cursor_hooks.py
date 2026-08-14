# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for Cursor hook validation (scripts/cursor_validation.py)."""

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cursor-hooks"
_SCRIPT = _ROOT / "scripts" / "cursor_validation.py"
_RUST_FMT_HOOK = _ROOT / ".cursor" / "hooks" / "rust-fmt.sh"
_SESSION_TRACK = _ROOT / ".cursor" / "hooks" / "session-track-edits.sh"

_spec = importlib.util.spec_from_file_location("cursor_validation", _SCRIPT)
cursor_validation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cursor_validation)  # type: ignore[union-attr]


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


_RUST_PATH = "crates/core/vlz/src/lib.rs"
_PY_PATH = "scripts/foo.py"


def _ok_history(commands: list[str]) -> dict:
    return {
        "conversation": {
            "last_shell_commands": commands,
            "last_shell_command_results": [{"exit_code": 0} for _ in commands],
        }
    }


def _stop_files(
    tmp_path: Path,
    *,
    pending: list[str] | None = None,
    turn: list[str] | None = None,
    baseline: int | None = None,
) -> tuple[Path, Path, Path]:
    pending_file = tmp_path / "pending.txt"
    turn_file = tmp_path / "turn.txt"
    baseline_file = tmp_path / "baseline.txt"
    if pending is not None:
        cursor_validation.write_session_edit_paths(
            tmp_path, pending, paths_file=pending_file
        )
    if turn is not None:
        cursor_validation.write_turn_edit_paths(
            tmp_path, turn, paths_file=turn_file
        )
    if baseline is not None:
        cursor_validation.write_shell_history_baseline(
            tmp_path, baseline, baseline_file=baseline_file
        )
    return pending_file, turn_file, baseline_file


def _resolve_stop(
    tmp_path: Path,
    hook_input: dict,
    pending_file: Path,
    turn_file: Path,
    baseline_file: Path | None = None,
) -> str | None:
    kwargs: dict = {
        "paths_file": pending_file,
        "turn_paths_file": turn_file,
    }
    if baseline_file is not None:
        kwargs["baseline_file"] = baseline_file
    return cursor_validation.resolve_stop_followup(hook_input, tmp_path, **kwargs)


def _rust_followup() -> str:
    return cursor_validation.build_followup_message(
        list(cursor_validation.RUST_SCOPED_TARGETS)
    )


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

    def test_includes_fuzz_harness_rust_for_formatting(self) -> None:
        # rust_paths feeds the rustfmt hook; keep harness .rs included.
        assert cursor_validation.rust_paths(
            [
                "crates/a.rs",
                "fuzz/fuzz_targets/fuzz_a.rs",
                "tests/fuzz/fuzz_targets/a.rs",
            ]
        ) == [
            "crates/a.rs",
            "fuzz/fuzz_targets/fuzz_a.rs",
            "tests/fuzz/fuzz_targets/a.rs",
        ]


class TestClassifyChangedPaths:
    def test_rust_only(self) -> None:
        targets = cursor_validation.classify_changed_paths([_RUST_PATH])
        assert targets == list(cursor_validation.RUST_SCOPED_TARGETS)

    def test_python_scripts(self) -> None:
        targets = cursor_validation.classify_changed_paths(["scripts/foo.py"])
        assert targets == ["make lint-python test-scripts"]

    def test_super_linter_yaml(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            [".github/workflows/ci.yml"]
        )
        assert targets == ["make super-linter"]

    def test_workflow_and_rust(self) -> None:
        paths = [_RUST_PATH, ".github/workflows/ci.yml"]
        targets = cursor_validation.classify_changed_paths(paths)
        assert "make super-linter" in targets
        assert cursor_validation.TARGET_FMT_CLIPPY in targets

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

    def test_cargo_fuzz_target_triggers_parity_not_crate_gates(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["fuzz/fuzz_targets/fuzz_config_toml.rs"]
        )
        assert targets == ["make check-fuzz-target-parity"]

    def test_afl_fuzz_target_triggers_parity_not_crate_gates(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["tests/fuzz/fuzz_targets/config_toml.rs"]
        )
        assert targets == ["make check-fuzz-target-parity"]

    def test_fuzz_parity_script_triggers_parity_and_python(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["scripts/check_fuzz_target_parity.py"]
        )
        assert "make lint-python test-scripts" in targets
        assert "make check-fuzz-target-parity" in targets

    def test_clusterfuzzlite_build_sh_triggers_lint_shell(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            [".clusterfuzzlite/build.sh"]
        )
        assert targets == ["make lint-shell"]

    def test_normalize_preserves_hidden_dir_dot(self) -> None:
        assert cursor_validation.normalize_repo_paths(
            ["./.clusterfuzzlite/build.sh", "./crates/a.rs"]
        ) == [".clusterfuzzlite/build.sh", "crates/a.rs"]

    def test_fuzz_cargo_toml_does_not_trigger_root_deny_gates(self) -> None:
        targets = cursor_validation.classify_changed_paths(["fuzz/Cargo.toml"])
        assert "make deny-check" not in targets
        assert "make cargo-check-locked" not in targets
        assert "make check-fuzz-target-parity" in targets

    def test_fuzz_corpus_only_does_not_trigger_parity(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["fuzz/corpus/fuzz_config_toml/valid_minimal"]
        )
        assert targets == []

    def test_afl_corpus_only_does_not_trigger_parity(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            ["tests/fuzz/corpus/config_toml/valid_minimal"]
        )
        assert targets == []

    def test_production_rust_and_fuzz_target_both(self) -> None:
        targets = cursor_validation.classify_changed_paths(
            [
                "crates/core/vlz/src/lib.rs",
                "fuzz/fuzz_targets/fuzz_go_mod.rs",
            ]
        )
        assert "make fmt-check clippy" in targets
        assert "make cargo-test" in targets
        assert "make check-fuzz-target-parity" in targets


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

    def test_prefixed_export_block_satisfies_rust_targets(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "export CARGO_TARGET_DIR=\"$PWD/target\"\n"
                    "make fmt-check clippy && make cargo-test"
                ],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is True

    def test_check_fast_does_not_satisfy_cargo_test(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make check-fast"],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is False
        assert (
            cursor_validation.targets_satisfied_by_history(
                data, ["make fmt-check clippy"]
            )
            is True
        )

    def test_check_fast_and_coverage_quick_rust_satisfy_rust_targets(
        self,
    ) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "make check-fast",
                    "make coverage-quick-rust",
                ],
                "last_shell_command_results": [
                    {"exit_code": 0},
                    {"exit_code": 0},
                ],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is True

    def test_check_pr_satisfies_fmt_clippy_and_cargo_test(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make check-pr"],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        targets = ["make fmt-check clippy", "make cargo-test"]
        assert cursor_validation.targets_satisfied_by_history(data, targets) is True

    def test_make_jobs_flag_satisfies_fmt_clippy(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": ["make -j check-fast"],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        assert (
            cursor_validation.targets_satisfied_by_history(
                data, ["make fmt-check clippy"]
            )
            is True
        )

    def test_make_directory_flag_satisfies_cargo_test(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "CARGO_TARGET_DIR=$PWD/target make -C /tmp cargo-test"
                ],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        assert (
            cursor_validation.targets_satisfied_by_history(
                data, ["make cargo-test"]
            )
            is True
        )

    def test_export_and_make_on_one_line(self) -> None:
        data = {
            "conversation": {
                "last_shell_commands": [
                    "export CARGO_TARGET_DIR=$PWD/target make fmt-check clippy"
                ],
                "last_shell_command_results": [{"exit_code": 0}],
            }
        }
        assert (
            cursor_validation.targets_satisfied_by_history(
                data, ["make fmt-check clippy"]
            )
            is True
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
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_PY_PATH], turn=[_PY_PATH]
        )
        msg = _resolve_stop(tmp_path, {}, pending_file, turn_file)
        assert msg == "Run: make lint-python test-scripts."
        assert cursor_validation.read_turn_edit_paths(
            tmp_path, paths_file=turn_file
        ) == []

    def test_returns_none_when_aborted(self, tmp_path: Path) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_PY_PATH], turn=[_PY_PATH]
        )
        assert (
            _resolve_stop(
                tmp_path, {"status": "aborted"}, pending_file, turn_file
            )
            is None
        )

    def test_stale_pending_without_turn_edits(self, tmp_path: Path) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_RUST_PATH]
        )
        assert _resolve_stop(tmp_path, {}, pending_file, turn_file) is None

    def test_rust_turn_paths_emit_scoped_targets(self, tmp_path: Path) -> None:
        pending_file, turn_file, _ = _stop_files(tmp_path, turn=[_RUST_PATH])
        msg = _resolve_stop(tmp_path, {}, pending_file, turn_file)
        assert msg == _rust_followup()

    def test_clears_pending_when_checks_succeeded(self, tmp_path: Path) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_RUST_PATH]
        )
        data = _ok_history(
            [
                cursor_validation.TARGET_FMT_CLIPPY,
                cursor_validation.TARGET_CARGO_TEST,
            ]
        )
        assert _resolve_stop(tmp_path, data, pending_file, turn_file) is None
        assert not pending_file.exists()

    def test_retries_when_last_check_failed(self, tmp_path: Path) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_RUST_PATH]
        )
        data = {
            "conversation": {
                "last_shell_commands": [cursor_validation.TARGET_CARGO_TEST],
                "last_shell_command_results": [{"exit_code": 1}],
            }
        }
        msg = _resolve_stop(tmp_path, data, pending_file, turn_file)
        assert msg == _rust_followup()

    def test_returns_none_for_unclassified_turn_paths(self, tmp_path: Path) -> None:
        pending_file, turn_file, _ = _stop_files(tmp_path, turn=["README.md"])
        assert _resolve_stop(tmp_path, {}, pending_file, turn_file) is None

    def test_clears_pending_when_turn_checks_already_succeeded(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, baseline_file = _stop_files(
            tmp_path,
            pending=[_RUST_PATH],
            turn=[_PY_PATH],
            baseline=0,
        )
        assert (
            _resolve_stop(
                tmp_path,
                _fixture("stop_skip_followup.json"),
                pending_file,
                turn_file,
                baseline_file,
            )
            is None
        )
        assert not pending_file.exists()

    def test_clears_pending_after_prefixed_compound(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_RUST_PATH]
        )
        data = _ok_history(
            [
                "export CARGO_TARGET_DIR=\"$PWD/target\"\n"
                f"{cursor_validation.TARGET_FMT_CLIPPY} && "
                f"{cursor_validation.TARGET_CARGO_TEST}"
            ]
        )
        assert _resolve_stop(tmp_path, data, pending_file, turn_file) is None
        assert not pending_file.exists()

    def test_silent_after_turn_clear_with_stale_pending(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_RUST_PATH], turn=[_RUST_PATH]
        )
        cursor_validation.clear_turn_edit_paths(
            tmp_path, paths_file=turn_file
        )
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=pending_file
        ) == [_RUST_PATH]
        assert _resolve_stop(tmp_path, {}, pending_file, turn_file) is None
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=pending_file
        ) == [_RUST_PATH]

    def test_ship_history_does_not_emit_with_leaked_turn_paths(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, baseline_file = _stop_files(
            tmp_path, pending=[_RUST_PATH], turn=[_RUST_PATH], baseline=0
        )
        data = _ok_history(
            [
                "make check-fast",
                "make coverage-quick-rust",
                "git checkout main && git pull --prune",
            ]
        )
        assert (
            _resolve_stop(
                tmp_path, data, pending_file, turn_file, baseline_file
            )
            is None
        )
        assert not pending_file.exists()

    def test_later_turn_edits_not_skipped_by_old_history(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, baseline_file = _stop_files(
            tmp_path, pending=[_RUST_PATH], turn=[_RUST_PATH]
        )
        prior = _ok_history(
            [
                cursor_validation.TARGET_FMT_CLIPPY,
                cursor_validation.TARGET_CARGO_TEST,
            ]
        )
        cursor_validation.snapshot_shell_history_baseline(
            prior, tmp_path, baseline_file=baseline_file
        )
        msg = _resolve_stop(
            tmp_path, prior, pending_file, turn_file, baseline_file
        )
        assert msg == _rust_followup()
        assert cursor_validation.read_session_edit_paths(
            tmp_path, paths_file=pending_file
        ) == [_RUST_PATH]

    def test_this_turn_checks_after_baseline_clear_pending(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, baseline_file = _stop_files(
            tmp_path, pending=[_RUST_PATH], turn=[_RUST_PATH]
        )
        cursor_validation.snapshot_shell_history_baseline(
            {
                "conversation": {
                    "last_shell_commands": [
                        cursor_validation.TARGET_FMT_CLIPPY,
                        cursor_validation.TARGET_CARGO_TEST,
                    ]
                }
            },
            tmp_path,
            baseline_file=baseline_file,
        )
        data = _ok_history(
            [
                cursor_validation.TARGET_FMT_CLIPPY,
                cursor_validation.TARGET_CARGO_TEST,
                cursor_validation.TARGET_FMT_CLIPPY,
                cursor_validation.TARGET_CARGO_TEST,
            ]
        )
        assert (
            _resolve_stop(
                tmp_path, data, pending_file, turn_file, baseline_file
            )
            is None
        )
        assert not pending_file.exists()

    def test_unknown_baseline_does_not_credit_old_history(
        self, tmp_path: Path
    ) -> None:
        pending_file, turn_file, _ = _stop_files(
            tmp_path, pending=[_RUST_PATH], turn=[_RUST_PATH]
        )
        data = _ok_history(
            [
                cursor_validation.TARGET_FMT_CLIPPY,
                cursor_validation.TARGET_CARGO_TEST,
            ]
        )
        msg = _resolve_stop(
            tmp_path,
            data,
            pending_file,
            turn_file,
            tmp_path / "missing-baseline.txt",
        )
        assert msg == _rust_followup()


class TestLoadHookJson:
    def test_parses_object(self) -> None:
        data = cursor_validation.load_hook_json('{"status": "completed"}')
        assert data == {"status": "completed"}

    def test_rejects_non_object(self) -> None:
        with pytest.raises(TypeError, match="JSON object"):
            cursor_validation.load_hook_json("[]")


class TestGetRepoRoot:
    def test_points_at_repository_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(
            cursor_validation.HOOK_REPO_ROOT_ENV, raising=False
        )
        assert cursor_validation.get_repo_root() == _ROOT

    def test_env_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(cursor_validation.HOOK_REPO_ROOT_ENV, str(tmp_path))
        assert cursor_validation.get_repo_root() == tmp_path


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


class TestSessionTrackTurnClearScript:
    def test_clears_turn_paths_and_keeps_pending(self, tmp_path: Path) -> None:
        pending = tmp_path / ".cursor" / ".agent-edited-paths"
        turn = tmp_path / ".cursor" / ".agent-turn-paths"
        pending.parent.mkdir(parents=True)
        pending.write_text("crates/core/vlz/src/lib.rs\n", encoding="utf-8")
        turn.write_text("crates/core/vlz/src/lib.rs\n", encoding="utf-8")
        payload = json.dumps(
            {
                "conversation": {
                    "last_shell_commands": ["make cargo-test", "git status"]
                }
            }
        )
        proc = subprocess.run(
            [str(_SESSION_TRACK), "turn-clear"],
            input=payload,
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "VLZ_CURSOR_HOOK_REPO_ROOT": str(tmp_path)},
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert pending.read_text(encoding="utf-8") == (
            "crates/core/vlz/src/lib.rs\n"
        )
        assert not turn.exists()
        assert cursor_validation.read_shell_history_baseline(tmp_path) == 2
