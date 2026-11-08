#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=duplicate-code  # CLI --check/main shape mirrors rustup_init_pins

"""Keep renovate.json constraints.rust aligned with rust-toolchain.toml.

Renovate postUpgradeTasks install Rust via containerbase using
constraints.rust. When that pin drifts behind rust-toolchain.toml channel,
Cargo-based hooks (SBOM, licenses, deny-check) fail. This helper reads the
toolchain channel as the single source of truth and syncs renovate.json.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

RUST_TOOLCHAIN_REL = Path("rust-toolchain.toml")
RENOVATE_JSON_REL = Path("renovate.json")

_CHANNEL_RE = re.compile(
    r'^channel\s*=\s*"(?P<channel>\d+\.\d+\.\d+)"\s*$',
    re.MULTILINE,
)


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def parse_rust_toolchain_channel(toolchain_text: str) -> str:
    """Return ``channel`` from rust-toolchain.toml text."""
    match = _CHANNEL_RE.search(toolchain_text)
    if match is None:
        raise SystemExit(
            f'{RUST_TOOLCHAIN_REL}: missing channel = "<semver>" pin'
        )
    return match.group("channel")


def read_renovate_rust_constraint(path: Path) -> str:
    """Return ``constraints.rust`` from renovate.json."""
    data = json.loads(path.read_text(encoding="utf-8"))
    constraints = data.get("constraints")
    if not isinstance(constraints, dict):
        raise SystemExit(f"{RENOVATE_JSON_REL}: missing constraints.rust")
    rust = constraints.get("rust")
    if not isinstance(rust, str) or not rust:
        raise SystemExit(f"{RENOVATE_JSON_REL}: missing constraints.rust")
    return rust


def write_renovate_rust_constraint(path: Path, channel: str) -> bool:
    """Set ``constraints.rust`` to ``channel``. Return True when rewritten."""
    text = path.read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    constraints = data.get("constraints")
    if not isinstance(constraints, dict):
        raise SystemExit(f"{RENOVATE_JSON_REL}: missing constraints object")
    if constraints.get("rust") == channel:
        return False
    constraints["rust"] = channel
    data["constraints"] = constraints
    # Preserve a trailing newline; Renovate JSON in-repo uses 2-space indent.
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return True


def sync_renovate_rust_constraint(root: Path, *, check: bool) -> bool:
    """
    Align renovate.json constraints.rust with rust-toolchain.toml channel.

    Returns True when drift exists (and writes unless ``check``).
    """
    channel = parse_rust_toolchain_channel(
        (root / RUST_TOOLCHAIN_REL).read_text(encoding="utf-8")
    )
    renovate_path = root / RENOVATE_JSON_REL
    current = read_renovate_rust_constraint(renovate_path)
    if current == channel:
        return False
    if check:
        return True
    write_renovate_rust_constraint(renovate_path, channel)
    return True


def main() -> int:
    """CLI entry point for Renovate post-upgrade and local --check."""
    parser = argparse.ArgumentParser(
        description=(
            "Keep renovate.json constraints.rust aligned with "
            "rust-toolchain.toml channel"
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when constraints.rust differs from the toolchain channel",
    )
    args = parser.parse_args()

    root = get_repo_root()
    channel = parse_rust_toolchain_channel(
        (root / RUST_TOOLCHAIN_REL).read_text(encoding="utf-8")
    )
    drift = sync_renovate_rust_constraint(root, check=args.check)
    if args.check and drift:
        current = read_renovate_rust_constraint(root / RENOVATE_JSON_REL)
        print(
            f"Error: {RENOVATE_JSON_REL} constraints.rust={current!r} "
            f"differs from {RUST_TOOLCHAIN_REL} channel={channel!r}. "
            "Run: PYTHONPATH=. python3 scripts/renovate_rust_constraint.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
