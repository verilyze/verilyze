# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cursor hook validation: path classification and follow-up messages."""

import json
import os
import re
from pathlib import Path

SUPER_LINTER_PATH_RE = re.compile(
    r"(^\.github/|\.ya?ml$|^biome\.json$|^renovate\.json$"
    r"|^\.gitleaks\.toml$|^\.commitlintrc\.json$"
    r"|^scripts/super-linter\.sh$)"
)

RUST_PATH_RE = re.compile(r"\.rs$")
PYTHON_SCRIPT_RE = re.compile(r"^(scripts/|tests/scripts/).*\.py$")
SHELL_SCRIPT_RE = re.compile(r"^scripts/.*\.sh$")


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


def rust_paths(paths: list[str]) -> list[str]:
    """Return paths ending in .rs."""
    return [p for p in paths if RUST_PATH_RE.search(p)]


def classify_changed_paths(paths: list[str]) -> list[str]:
    """Map changed paths to make target strings (deduplicated, ordered)."""
    targets: list[str] = []
    normalized = [p.replace("\\", "/").lstrip("./") for p in paths if p]

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
    normalized = [p.replace("\\", "/").lstrip("./") for p in paths if p]
    return any(SUPER_LINTER_PATH_RE.search(p) for p in normalized)


def build_followup_message(targets: list[str]) -> str:
    """Build stop-hook follow-up text for the agent."""
    if not targets:
        return "Run make check-fast before push if you changed behavior."
    body = "; ".join(targets)
    return f"Run: {body}. Then make check-fast before push."


def should_skip_followup(hook_input: dict, targets: list[str]) -> bool:
    """Skip follow-up when shell history already ran a recommended target."""
    conversation = hook_input.get("conversation")
    if not isinstance(conversation, dict):
        return False
    history = conversation.get("last_shell_commands")
    if not isinstance(history, list):
        return False
    history_text = " ".join(str(item) for item in history)
    return any(target in history_text for target in targets)


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
