# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cursor hook validation: path classification and follow-up messages."""

import json
import os
import re
import subprocess  # nosec B404
from pathlib import Path

SUPER_LINTER_PATH_RE = re.compile(
    r"(^\.github/|\.ya?ml$|^biome\.json$|^renovate\.json$"
    r"|^\.gitleaks\.toml$|^\.commitlintrc\.json$"
    r"|^scripts/super-linter\.sh$|^packaging/.*\.env$"
    r"|^packaging/.*/Dockerfile$)"
)

RUST_PATH_RE = re.compile(r"\.rs$")
PYTHON_SCRIPT_RE = re.compile(r"^(scripts/|tests/scripts/).*\.py$")
SHELL_SCRIPT_RE = re.compile(r"^(scripts/|\.clusterfuzzlite/).*\.sh$")
CARGO_MANIFEST_RE = re.compile(r"(^|/)Cargo\.toml$")
# Paths under AFL or cargo-fuzz trees (skip root deny / clippy gates).
FUZZ_TREE_RE = re.compile(r"^(tests/fuzz/|fuzz/)")
# Basename parity only cares about harness sources and manifests, not corpora.
FUZZ_PARITY_PATH_RE = re.compile(
    r"^(?:tests/fuzz|fuzz)/(?:fuzz_targets/|Cargo\.toml)"
    r"|^scripts/check_fuzz_target_parity\.py$"
)
PYPROJECT_MANIFEST = "pyproject.toml"


def touches_cargo_dependency_manifest(paths: list[str]) -> bool:
    """True when root-workspace Cargo.toml or Cargo.lock changed."""
    return any(
        p == "Cargo.lock"
        or (CARGO_MANIFEST_RE.search(p) and not FUZZ_TREE_RE.search(p))
        for p in paths
    )


def touches_fuzz_parity_paths(paths: list[str]) -> bool:
    """True when AFL/cargo-fuzz harness or parity-script paths changed."""
    return any(FUZZ_PARITY_PATH_RE.search(p) for p in paths)


def is_production_rust_path(path: str) -> bool:
    """True for .rs outside AFL / cargo-fuzz harness trees."""
    return bool(RUST_PATH_RE.search(path)) and not FUZZ_TREE_RE.search(path)


def touches_deny_policy(paths: list[str]) -> bool:
    """True when deny.toml changed."""
    return "deny.toml" in paths


def touches_pyproject_manifest(paths: list[str]) -> bool:
    """True when pyproject.toml changed."""
    return PYPROJECT_MANIFEST in paths


TARGET_FMT_CLIPPY = "make fmt-check clippy"
TARGET_CARGO_TEST = "make cargo-test"
# Follow-up emitted when production .rs files change (ci-validation.mdc).
RUST_SCOPED_TARGETS = (TARGET_FMT_CLIPPY, TARGET_CARGO_TEST)

SESSION_EDIT_PATHS_REL = ".cursor/.agent-edited-paths"
TURN_EDIT_PATHS_REL = ".cursor/.agent-turn-paths"
SHELL_HISTORY_BASELINE_REL = ".cursor/.agent-shell-baseline"
HOOK_REPO_ROOT_ENV = "VLZ_CURSOR_HOOK_REPO_ROOT"


def hooks_disabled() -> bool:
    """True when VLZ_CURSOR_HOOKS_DISABLE is set to a truthy value."""
    return os.environ.get("VLZ_CURSOR_HOOKS_DISABLE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def parse_edited_paths(hook_input: dict) -> list[str]:
    """Extract edited file paths from Cursor afterFileEdit hook JSON."""
    paths: list[str] = []
    for key in ("file_path", "path"):
        value = hook_input.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    edits = hook_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                for key in ("file_path", "path"):
                    value = edit.get(key)
                    if isinstance(value, str) and value:
                        paths.append(value)
    files = hook_input.get("files")
    if isinstance(files, list):
        for item in files:
            if isinstance(item, str) and item:
                paths.append(item)
    return list(dict.fromkeys(paths))


def normalize_repo_paths(paths: list[str]) -> list[str]:
    """Normalize path strings for classification.

    Strip only ``./`` prefixes. Do not use ``str.lstrip("./")``, which would
    also strip the leading ``.`` from hidden paths such as ``.github/`` or
    ``.clusterfuzzlite/``.
    """
    normalized: list[str] = []
    for path in paths:
        if not path:
            continue
        path = path.replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        normalized.append(path)
    return normalized


def _git_output(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(  # nosec B603 B607
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def collect_changed_paths(repo_root: Path) -> list[str]:
    """Collect paths from working tree, index, and unpushed commits."""
    paths: list[str] = []
    for args in (
        ("diff", "--name-only"),
        ("diff", "--cached", "--name-only"),
    ):
        output = _git_output(repo_root, *args)
        if output.strip():
            paths.extend(output.splitlines())

    base = ""
    for args in (
        ("merge-base", "origin/main", "HEAD"),
        ("merge-base", "main", "HEAD"),
    ):
        base = _git_output(repo_root, *args).strip()
        if base:
            break
    if base:
        output = _git_output(repo_root, "diff", "--name-only", f"{base}..HEAD")
        if output.strip():
            paths.extend(output.splitlines())

    return list(dict.fromkeys(paths))


def rust_paths(paths: list[str]) -> list[str]:
    """Return paths ending in .rs (including fuzz harnesses for rustfmt)."""
    return [p for p in paths if RUST_PATH_RE.search(p)]


def classify_changed_paths(paths: list[str]) -> list[str]:
    """Map changed paths to make target strings (deduplicated, ordered)."""
    targets: list[str] = []
    normalized = normalize_repo_paths(paths)

    if any(is_production_rust_path(p) for p in normalized):
        targets.extend(RUST_SCOPED_TARGETS)
    if any(PYTHON_SCRIPT_RE.search(p) for p in normalized):
        targets.append("make lint-python test-scripts")
    if any(SHELL_SCRIPT_RE.search(p) for p in normalized):
        targets.append("make lint-shell")
    if any(
        p.startswith("architecture/") and p.endswith(".mmd")
        for p in normalized
    ):
        targets.append("make check-doc-diagrams")
    if any(
        p.startswith("man/") or p == "verilyze.conf.example"
        for p in normalized
    ):
        targets.append("make check-config-docs")
        if any(p.startswith("man/") for p in normalized):
            targets.append("make check-manpages")
    if any(p.startswith("packaging/") for p in normalized):
        targets.append("make check-packaging")
    if touches_cargo_dependency_manifest(normalized):
        targets.extend(
            [
                "make cargo-check-locked",
                "make deny-check",
                "make check-third-party-licenses",
                "make check-sbom",
            ]
        )
    elif touches_deny_policy(normalized):
        targets.extend(
            [
                "make deny-check",
                "make check-third-party-licenses",
            ]
        )
    if touches_pyproject_manifest(normalized):
        targets.append("make check-sbom")
    if touches_fuzz_parity_paths(normalized):
        targets.append("make check-fuzz-target-parity")
    if any(SUPER_LINTER_PATH_RE.search(p) for p in normalized):
        targets.append("make super-linter")

    return list(dict.fromkeys(targets))


def needs_super_linter(paths: list[str]) -> bool:
    """True when local super-linter is recommended."""
    normalized = normalize_repo_paths(paths)
    return any(SUPER_LINTER_PATH_RE.search(p) for p in normalized)


def _state_file(
    repo_root: Path,
    relative: str,
    *,
    paths_file: Path | None = None,
) -> Path:
    if paths_file is not None:
        return paths_file
    return repo_root / relative


def _read_path_list(path: Path) -> list[str]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return normalize_repo_paths([line for line in lines if line.strip()])


def _write_path_list(path: Path, paths: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = normalize_repo_paths(paths)
    if normalized:
        path.write_text("\n".join(normalized) + "\n", encoding="utf-8")
    elif path.is_file():
        path.unlink()


def _append_path_list(path: Path, paths: list[str]) -> None:
    merged = list(
        dict.fromkeys([*_read_path_list(path), *normalize_repo_paths(paths)])
    )
    _write_path_list(path, merged)


def session_edit_paths_file(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
) -> Path:
    """Return the pending validation tracking file path."""
    return _state_file(
        repo_root, SESSION_EDIT_PATHS_REL, paths_file=paths_file
    )


def turn_edit_paths_file(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
) -> Path:
    """Return the per-turn edit tracking file path."""
    return _state_file(repo_root, TURN_EDIT_PATHS_REL, paths_file=paths_file)


def read_session_edit_paths(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
) -> list[str]:
    """Read normalized paths pending validation since last successful check."""
    return _read_path_list(
        session_edit_paths_file(repo_root, paths_file=paths_file)
    )


def read_turn_edit_paths(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
) -> list[str]:
    """Read normalized paths edited by the agent in the current turn."""
    return _read_path_list(
        turn_edit_paths_file(repo_root, paths_file=paths_file)
    )


def write_session_edit_paths(
    repo_root: Path,
    paths: list[str],
    *,
    paths_file: Path | None = None,
) -> None:
    """Replace pending validation paths."""
    _write_path_list(
        session_edit_paths_file(repo_root, paths_file=paths_file), paths
    )


def write_turn_edit_paths(
    repo_root: Path,
    paths: list[str],
    *,
    paths_file: Path | None = None,
) -> None:
    """Replace per-turn edit paths."""
    _write_path_list(
        turn_edit_paths_file(repo_root, paths_file=paths_file), paths
    )


def clear_session_edit_paths(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
) -> None:
    """Clear pending validation tracking."""
    write_session_edit_paths(repo_root, [], paths_file=paths_file)


def clear_turn_edit_paths(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
) -> None:
    """Clear per-turn edit tracking."""
    write_turn_edit_paths(repo_root, [], paths_file=paths_file)


def append_session_edit_paths(
    repo_root: Path,
    paths: list[str],
    *,
    paths_file: Path | None = None,
) -> None:
    """Append unique normalized paths to the pending validation list."""
    _append_path_list(
        session_edit_paths_file(repo_root, paths_file=paths_file), paths
    )


def append_turn_edit_paths(
    repo_root: Path,
    paths: list[str],
    *,
    paths_file: Path | None = None,
) -> None:
    """Append unique normalized paths to the current turn edit list."""
    _append_path_list(
        turn_edit_paths_file(repo_root, paths_file=paths_file), paths
    )


def append_agent_edit_paths(
    repo_root: Path,
    paths: list[str],
    *,
    paths_file: Path | None = None,
    turn_paths_file: Path | None = None,
) -> None:
    """Append paths to both pending validation and current turn tracking."""
    append_session_edit_paths(repo_root, paths, paths_file=paths_file)
    append_turn_edit_paths(
        repo_root,
        paths,
        paths_file=turn_paths_file,
    )


def clear_agent_edit_paths(
    repo_root: Path,
    *,
    paths_file: Path | None = None,
    turn_paths_file: Path | None = None,
    baseline_file: Path | None = None,
) -> None:
    """Clear pending validation, current turn tracking, and shell baseline."""
    clear_session_edit_paths(repo_root, paths_file=paths_file)
    clear_turn_edit_paths(repo_root, paths_file=turn_paths_file)
    clear_shell_history_baseline(repo_root, baseline_file=baseline_file)


def shell_history_baseline_file(
    repo_root: Path,
    *,
    baseline_file: Path | None = None,
) -> Path:
    """Return the per-prompt shell-history baseline file path."""
    return _state_file(
        repo_root, SHELL_HISTORY_BASELINE_REL, paths_file=baseline_file
    )


def read_shell_history_baseline(
    repo_root: Path,
    *,
    baseline_file: Path | None = None,
) -> int | None:
    """Return command-count snapshot from the last user prompt, if present."""
    path = shell_history_baseline_file(repo_root, baseline_file=baseline_file)
    if not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw.isdigit():
        return None
    return int(raw)


def write_shell_history_baseline(
    repo_root: Path,
    count: int,
    *,
    baseline_file: Path | None = None,
) -> None:
    """Record how many shell commands existed at the start of this prompt."""
    path = shell_history_baseline_file(repo_root, baseline_file=baseline_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{count}\n", encoding="utf-8")


def clear_shell_history_baseline(
    repo_root: Path,
    *,
    baseline_file: Path | None = None,
) -> None:
    """Remove the shell-history baseline snapshot."""
    path = shell_history_baseline_file(repo_root, baseline_file=baseline_file)
    if path.is_file():
        path.unlink()


def snapshot_shell_history_baseline(
    hook_input: dict,
    repo_root: Path,
    *,
    baseline_file: Path | None = None,
) -> None:
    """Snapshot last_shell_commands length at prompt submit.

    Clear the snapshot when the hook payload has no command list.
    """
    conversation = hook_input.get("conversation")
    history = (
        conversation.get("last_shell_commands")
        if isinstance(conversation, dict)
        else None
    )
    if not isinstance(history, list):
        clear_shell_history_baseline(repo_root, baseline_file=baseline_file)
        return
    write_shell_history_baseline(
        repo_root, len(history), baseline_file=baseline_file
    )


def stop_status_aborted(hook_input: dict) -> bool:
    """True when the stop hook reports an aborted agent turn."""
    status = hook_input.get("status")
    return isinstance(status, str) and status == "aborted"


def build_followup_message(
    targets: list[str],
    paths: list[str] | None = None,
) -> str:
    """Build stop-hook follow-up text for the agent."""
    _ = paths
    if not targets:
        return ""
    return f"Run: {'; '.join(targets)}."


# Recorded `make <args>` that imply scoped stop-hook targets.
# Keep in sync with Makefile: check-fast runs fmt-check+clippy
# (not cargo-test); check-pr / check include coverage
# (treated as cargo-test here).
_MAKE_ARGS_IMPLY: dict[str, tuple[str, ...]] = {
    TARGET_FMT_CLIPPY.removeprefix("make "): (TARGET_FMT_CLIPPY,),
    "check-fast": (TARGET_FMT_CLIPPY,),
    "check-pr": RUST_SCOPED_TARGETS,
    "check": RUST_SCOPED_TARGETS,
    TARGET_CARGO_TEST.removeprefix("make "): (TARGET_CARGO_TEST,),
    "unit-tests": (TARGET_CARGO_TEST,),
    "coverage-quick": (TARGET_CARGO_TEST,),
    "coverage-quick-rust": (TARGET_CARGO_TEST,),
}

_SHELL_EXPORT = "export"
_MAKE_END_OF_OPTIONS = "--"
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _strip_env_prefixes(command: str) -> str:
    """Remove leading VAR=value and export VAR=value tokens."""
    parts = command.split()
    index = 0
    while index < len(parts):
        token = parts[index]
        if token == _SHELL_EXPORT and index + 1 < len(parts):
            nxt = parts[index + 1]
            if _ENV_ASSIGNMENT_RE.match(nxt):
                index += 2
                continue
        if _ENV_ASSIGNMENT_RE.match(token):
            index += 1
            continue
        break
    return " ".join(parts[index:])


_MAKE_FLAGS_WITH_ARG = {
    "-C",
    "--directory",
    "-f",
    "--file",
    "-I",
    "--include-dir",
    "-O",
    "--output-sync",
}


def _make_recipe_args(stripped: str) -> str | None:
    """Return make target args after skipping GNU Make flags, or None."""
    tokens = stripped.split()
    if not tokens or tokens[0] != "make":
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == _MAKE_END_OF_OPTIONS:
            index += 1
            break
        if not token.startswith("-"):
            break
        if "=" in token:
            index += 1
            continue
        if token in _MAKE_FLAGS_WITH_ARG:
            index += 2
            continue
        if token in {"-j", "--jobs"} and index + 1 < len(tokens):
            nxt = tokens[index + 1]
            if nxt[:1].isdigit():
                index += 2
                continue
        index += 1
    if index >= len(tokens):
        return None
    return " ".join(tokens[index:])


def _targets_implied_by_segment(segment: str) -> set[str]:
    """Return scoped make targets implied by one shell segment."""
    stripped = _strip_env_prefixes(segment.strip())
    if not stripped:
        return set()
    implied: set[str] = set()
    make_args = _make_recipe_args(stripped)
    if make_args is None:
        return implied
    for recorded, targets in sorted(
        _MAKE_ARGS_IMPLY.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if make_args == recorded or make_args.startswith(f"{recorded} "):
            implied.update(targets)
    return implied


def _command_matches_target(command: str, target: str) -> bool:
    stripped = _strip_env_prefixes(command.strip())
    if stripped == target or stripped.startswith(f"{target} "):
        return True
    return target in _targets_implied_by_segment(command)


def _split_command_segments(command: str) -> list[str]:
    segments: list[str] = []
    for line in command.splitlines():
        for part in re.split(r"[;&]|&&", line):
            stripped = part.strip()
            if stripped:
                segments.append(stripped)
    return segments


def _shell_history_pairs(
    hook_input: dict,
) -> list[tuple[str, dict | None]] | None:
    conversation = hook_input.get("conversation")
    if not isinstance(conversation, dict):
        return None
    history = conversation.get("last_shell_commands")
    if not isinstance(history, list) or not history:
        return None
    results = conversation.get("last_shell_command_results")
    if not isinstance(results, list) or len(results) != len(history):
        return None
    pairs: list[tuple[str, dict | None]] = []
    for cmd, result in zip(history, results, strict=True):
        pairs.append((str(cmd), result if isinstance(result, dict) else None))
    return pairs


def targets_satisfied_by_history(
    hook_input: dict,
    targets: list[str],
    *,
    pairs: list[tuple[str, dict | None]] | None = None,
) -> bool:
    """True when every target succeeded in the (optionally sliced) history."""
    if not targets:
        return False
    if pairs is None:
        pairs = _shell_history_pairs(hook_input)
    if pairs is None:
        return False

    satisfied: set[str] = set()
    for cmd, result in pairs:
        exit_code = result.get("exit_code") if result is not None else None
        if exit_code is None or exit_code != 0:
            continue
        for segment in _split_command_segments(cmd):
            for target in targets:
                if target not in satisfied and _command_matches_target(
                    segment, target
                ):
                    satisfied.add(target)
    return satisfied == set(targets)


def _pairs_for_satisfaction(
    hook_input: dict,
    turn_paths: list[str],
    baseline: int | None,
) -> list[tuple[str, dict | None]] | None:
    """Shell pairs that may credit checks for this prompt.

    When a prompt-start baseline exists, ignore older commands. When this turn
    edited files and the baseline is unknown, credit nothing (do not skip).
    """
    pairs = _shell_history_pairs(hook_input)
    if pairs is None:
        return None
    if baseline is not None:
        return pairs[baseline:]
    if turn_paths:
        return []
    return pairs


def last_target_command_failed(hook_input: dict, targets: list[str]) -> bool:
    """True when the latest shell command matched a target and failed."""
    if not targets:
        return False
    pairs = _shell_history_pairs(hook_input)
    if pairs is None:
        return False

    last_cmd, last_result = pairs[-1]
    exit_code = (
        last_result.get("exit_code") if last_result is not None else None
    )
    if exit_code is None or exit_code == 0:
        return False
    for segment in _split_command_segments(last_cmd):
        if any(_command_matches_target(segment, target) for target in targets):
            return True
    return False


def should_skip_followup(
    hook_input: dict,
    targets: list[str],
    *,
    pairs: list[tuple[str, dict | None]] | None = None,
) -> bool:
    """Skip follow-up when all required targets succeeded in shell history."""
    return targets_satisfied_by_history(hook_input, targets, pairs=pairs)


def should_emit_followup(
    hook_input: dict,
    turn_paths: list[str],
    pending_paths: list[str],
    targets: list[str],
    *,
    pairs: list[tuple[str, dict | None]] | None = None,
) -> bool:
    """True when the stop hook should auto-submit a scoped check follow-up."""
    if stop_status_aborted(hook_input):
        return False
    if not targets:
        return False
    if should_skip_followup(hook_input, targets, pairs=pairs):
        return False
    if turn_paths:
        return True
    if pending_paths and last_target_command_failed(hook_input, targets):
        return True
    return False


def resolve_stop_followup(
    hook_input: dict,
    repo_root: Path,
    *,
    paths_file: Path | None = None,
    turn_paths_file: Path | None = None,
    baseline_file: Path | None = None,
) -> str | None:
    """Return follow-up text, or None when the stop hook should stay silent."""
    pending_paths = read_session_edit_paths(repo_root, paths_file=paths_file)
    turn_paths = read_turn_edit_paths(
        repo_root,
        paths_file=turn_paths_file,
    )
    baseline = read_shell_history_baseline(
        repo_root, baseline_file=baseline_file
    )
    sat_pairs = _pairs_for_satisfaction(hook_input, turn_paths, baseline)
    try:
        if stop_status_aborted(hook_input):
            return None

        if pending_paths:
            pending_targets = classify_changed_paths(pending_paths)
            if pending_targets and targets_satisfied_by_history(
                hook_input,
                pending_targets,
                pairs=sat_pairs,
            ):
                clear_session_edit_paths(repo_root, paths_file=paths_file)
                return None

        if turn_paths:
            validation_paths = turn_paths
        elif pending_paths and last_target_command_failed(
            hook_input,
            classify_changed_paths(pending_paths),
        ):
            validation_paths = pending_paths
        else:
            return None

        targets = classify_changed_paths(validation_paths)
        if not targets:
            return None
        if not should_emit_followup(
            hook_input,
            turn_paths,
            pending_paths,
            targets,
            pairs=sat_pairs,
        ):
            if targets_satisfied_by_history(
                hook_input, targets, pairs=sat_pairs
            ):
                clear_session_edit_paths(repo_root, paths_file=paths_file)
            return None

        message = build_followup_message(targets, validation_paths)
        return message or None
    finally:
        clear_turn_edit_paths(repo_root, paths_file=turn_paths_file)


def load_hook_json(raw: str) -> dict:
    """Parse hook JSON stdin."""
    data = json.loads(raw)
    if not isinstance(data, dict):
        msg = "hook input must be a JSON object"
        raise TypeError(msg)
    return data


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    override = os.environ.get(HOOK_REPO_ROOT_ENV, "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent
