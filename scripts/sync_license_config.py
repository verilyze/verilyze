#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Sync accepted licenses from deny.toml to about.toml.

Single source of truth: deny.toml [licenses] allow.
Run from repository root:
  python scripts/sync_license_config.py

Updates about.toml accepted = [...] to match deny.toml [licenses] allow.
Preserves all other about.toml content (workarounds, private, etc.).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def extract_allow_from_deny(deny_path: Path) -> list[str]:
    """Extract [licenses] allow list from deny.toml."""
    with open(deny_path, "rb") as f:
        data = tomllib.load(f)
    try:
        licenses_section = data["licenses"]
        allow = licenses_section["allow"]
        if not isinstance(allow, list):
            raise ValueError("licenses.allow must be a list")
        return [str(item) for item in allow]
    except KeyError as e:
        raise SystemExit(f"Error: {deny_path} missing required key {e}") from e


def update_about_accepted(about_path: Path, accepted: list[str]) -> bool:
    """
    Update accepted array in about.toml. Returns True if file was changed.
    Preserves all other content. Compares semantically (list equality).
    """
    content = about_path.read_text(encoding="utf-8")

    # Parse current accepted to check semantic equality
    try:
        data = tomllib.loads(content)
        current = [str(x) for x in data.get("accepted", [])]
        if current == accepted:
            return False
    except tomllib.TOMLDecodeError:
        pass

    # Build new accepted block (match typical cargo-about format)
    items = ",\n".join(f'    "{item}"' for item in accepted)
    new_block = f"accepted = [\n{items},\n]"

    # Replace existing accepted = [...] (multiline or single-line)
    pattern = r"accepted\s*=\s*\[[^\]]*\]"
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        raise SystemExit(
            f"Error: {about_path} has no accepted = [...] block"
        ) from None

    new_content = content[: match.start()] + new_block + content[match.end() :]
    about_path.write_text(new_content, encoding="utf-8")
    return True


def sync_license_config(deny_path: Path, about_path: Path) -> bool:
    """
    Sync deny.toml [licenses] allow to about.toml accepted.
    Returns True if about.toml was changed.
    """
    allow = extract_allow_from_deny(deny_path)
    return update_about_accepted(about_path, allow)


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Sync accepted licenses from deny.toml to about.toml"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify about.toml matches deny.toml; exit 1 if out of sync",
    )
    args = parser.parse_args()

    repo_root = get_repo_root()
    deny_path = repo_root / "deny.toml"
    about_path = repo_root / "about.toml"

    if not deny_path.exists():
        print(f"Error: {deny_path} not found", file=sys.stderr)
        return 1
    if not about_path.exists():
        print(f"Error: {about_path} not found", file=sys.stderr)
        return 1

    if args.check:
        original = about_path.read_text(encoding="utf-8")
        changed = sync_license_config(deny_path, about_path)
        if changed:
            about_path.write_text(original, encoding="utf-8")
            print(
                "Error: about.toml accepted is out of sync with deny.toml. "
                "Run: make sync-license-config",
                file=sys.stderr,
            )
            return 1
        return 0
    changed = sync_license_config(deny_path, about_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
