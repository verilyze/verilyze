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
SHELL_SCRIPT_RE = re.compile(r"^scripts/.*\.sh$")

CHECK_FAST_BASELINE = "Run make check-fast before push."


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
    """Normalize path strings for classification."""
    return [p.replace("\\", "/").lstrip("./") for p in paths if p]


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
    """Return paths ending in .rs."""
    return [p for p in paths if RUST_PATH_RE.search(p)]


def classify_changed_paths(paths: list[str]) -> list[str]:
    """Map changed paths to make target strings (deduplicated, ordered)."""
    targets: list[str] = []
    normalized = normalize_repo_paths(paths)

    if any(RUST_PATH_RE.search(p) for p in normalized):
        targets.extend(["make fmt-check clippy", "make cargo-test"])
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
    if any(
        p in ("Cargo.toml", "deny.toml") or p.endswith("/Cargo.toml")
        for p in normalized
    ):
        targets.append("make deny-check")
    if any(SUPER_LINTER_PATH_RE.search(p) for p in normalized):
        targets.append("make super-linter")

    return list(dict.fromkeys(targets))


def needs_super_linter(paths: list[str]) -> bool:
    """True when local super-linter is recommended."""
    normalized = normalize_repo_paths(paths)
    return any(SUPER_LINTER_PATH_RE.search(p) for p in normalized)


def _format_changed_paths(paths: list[str]) -> str:
    normalized = normalize_repo_paths(paths)
    if not normalized:
        return ""
    if len(normalized) <= 8:
        return ", ".join(normalized)
    head = ", ".join(normalized[:8])
    return f"{head}, ..."


def build_followup_message(
    targets: list[str],
    paths: list[str] | None = None,
) -> str:
    """Build stop-hook follow-up text for the agent."""
    changed = _format_changed_paths(paths or [])
    if targets:
        body = "; ".join(targets)
        return f"Run: {body}. Then {CHECK_FAST_BASELINE}"
    if changed:
        return f"{CHECK_FAST_BASELINE} Changed paths: {changed}."
    return CHECK_FAST_BASELINE


def _command_matches_target(command: str, target: str) -> bool:
    stripped = command.strip()
    return stripped == target or stripped.startswith(f"{target} ")


def should_skip_followup(hook_input: dict, targets: list[str]) -> bool:
    """Skip follow-up when the latest shell command succeeded on a target."""
    if not targets:
        return False
    conversation = hook_input.get("conversation")
    if not isinstance(conversation, dict):
        return False
    history = conversation.get("last_shell_commands")
    if not isinstance(history, list) or not history:
        return False

    last_cmd = str(history[-1])
    if not any(
        _command_matches_target(last_cmd, target) for target in targets
    ):
        return False

    results = conversation.get("last_shell_command_results")
    if isinstance(results, list) and len(results) == len(history):
        last_result = results[-1]
        if isinstance(last_result, dict):
            exit_code = last_result.get("exit_code")
            if exit_code is not None and exit_code != 0:
                return False

    return True


def load_hook_json(raw: str) -> dict:
    """Parse hook JSON stdin."""
    data = json.loads(raw)
    if not isinstance(data, dict):
        msg = "hook input must be a JSON object"
        raise TypeError(msg)
    return data


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent
