#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Sync deny.toml [bans.skip] crate version pins with Cargo.lock.

Renovate patch bumps can leave bans.skip entries stale (for example
base64@0.23.0 while Cargo.lock resolves base64 0.23.1). This script updates
existing skip entries when the pinned version is gone but exactly one same
major.minor version remains in the lockfile. When the crate is missing from
Cargo.lock, or no lock version shares the pinned major.minor, the obsolete
skip line is removed. New duplicate versions still need a manual skip entry
with a documented reason.

Run from repository root:
  python3 scripts/sync_deny_skips.py
  python3 scripts/sync_deny_skips.py --check
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

# Sentinel returned by find_replacement_version when the skip must be removed.
DROP_SKIP = "__DROP_SKIP__"


class SyncDenySkipsError(Exception):
    """Raised when skip pins cannot be synced safely."""


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def parse_cargo_lock_versions(lock_path: Path) -> dict[str, list[str]]:
    """Map crate name to resolved versions listed in Cargo.lock."""
    versions: dict[str, list[str]] = {}
    current_name: str | None = None
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("name = "):
            current_name = line.split('"')[1]
        elif line.startswith("version = ") and current_name is not None:
            version = line.split('"')[1]
            versions.setdefault(current_name, []).append(version)
            current_name = None
    return versions


def parse_skip_spec(spec: str) -> tuple[str, str]:
    """Split ``crate@version`` skip spec into name and version."""
    if "@" not in spec:
        msg = f"invalid skip crate spec (expected name@version): {spec!r}"
        raise SyncDenySkipsError(msg)
    name, version = spec.rsplit("@", 1)
    if not name or not version:
        msg = f"invalid skip crate spec (expected name@version): {spec!r}"
        raise SyncDenySkipsError(msg)
    return name, version


def major_minor(version: str) -> tuple[int, int]:
    """Return major and minor components for a semver ``x.y.z`` string."""
    parts = version.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        msg = f"invalid semver for skip sync: {version!r}"
        raise SyncDenySkipsError(msg)
    return int(parts[0]), int(parts[1])


def find_replacement_version(
    crate_name: str,
    pinned_version: str,
    lock_versions: dict[str, list[str]],
) -> str | None:
    """
    Return a lockfile version replacing ``pinned_version``, DROP_SKIP, or None.

    Returns None when ``pinned_version`` is still present in the lockfile.
    Returns a replacement when the pin is absent and exactly one lock version
    shares its major.minor prefix. Returns DROP_SKIP when the crate is missing
    or no lock version shares that major.minor (obsolete skip).
    """
    resolved = lock_versions.get(crate_name, [])
    if pinned_version in resolved:
        return None
    if not resolved:
        return DROP_SKIP

    prefix = major_minor(pinned_version)
    candidates = [ver for ver in resolved if major_minor(ver) == prefix]
    if not candidates:
        return DROP_SKIP
    if len(candidates) > 1:
        joined = ", ".join(candidates)
        msg = (
            f"skip crate {crate_name}@{pinned_version} is ambiguous; "
            f"multiple lock versions share major.minor: {joined}"
        )
        raise SyncDenySkipsError(msg)
    replacement = candidates[0]
    if replacement == pinned_version:
        return None
    return replacement


def extract_skip_specs(deny_path: Path) -> list[str]:
    """Return ``crate@version`` values from ``[bans.skip]``."""
    with open(deny_path, "rb") as handle:
        data = tomllib.load(handle)
    try:
        skip_entries = data["bans"]["skip"]
    except KeyError as exc:
        msg = f"Error: {deny_path} missing required key {exc}"
        raise SystemExit(msg) from exc
    if not isinstance(skip_entries, list):
        raise SystemExit(f"Error: {deny_path} bans.skip must be a list")
    specs: list[str] = []
    for entry in skip_entries:
        if not isinstance(entry, dict):
            msg = f"Error: {deny_path} bans.skip entries must be tables"
            raise SystemExit(msg)
        crate = entry.get("crate")
        if not isinstance(crate, str):
            msg = f"Error: {deny_path} bans.skip entry missing crate"
            raise SystemExit(msg)
        specs.append(crate)
    return specs


def apply_skip_updates(
    content: str,
    updates: list[tuple[str, str, str]],
) -> str:
    """Replace ``name@old`` skip pins with ``name@new`` in deny.toml."""
    updated = content
    for name, old_version, new_version in updates:
        old_spec = f"{name}@{old_version}"
        new_spec = f"{name}@{new_version}"
        pattern = rf'(\{{ crate = "){re.escape(old_spec)}(")'
        updated, count = re.subn(pattern, rf"\1{new_spec}\2", updated, count=1)
        if count != 1:
            msg = f"deny.toml missing skip entry for {old_spec}"
            raise SyncDenySkipsError(msg)
    return updated


def apply_skip_drops(content: str, drops: list[str]) -> str:
    """Remove whole ``{ crate = "...", reason = "..." },`` skip lines."""
    updated = content
    for spec in drops:
        pattern = (
            rf'^[ \t]*\{{ crate = "{re.escape(spec)}", '
            rf'reason = "[^"]*" \}},\n'
        )
        updated, count = re.subn(
            pattern, "", updated, count=1, flags=re.MULTILINE
        )
        if count != 1:
            msg = f"deny.toml missing skip entry for {spec}"
            raise SyncDenySkipsError(msg)
    return updated


def sync_deny_skips(
    deny_path: Path,
    lock_path: Path,
    *,
    check: bool = False,
) -> bool:
    """
    Sync skip version pins in deny.toml with Cargo.lock.

    Returns True when deny.toml would change or is out of sync in check mode.
    """
    lock_versions = parse_cargo_lock_versions(lock_path)
    updates: list[tuple[str, str, str]] = []
    drops: list[str] = []
    for spec in extract_skip_specs(deny_path):
        name, pinned = parse_skip_spec(spec)
        replacement = find_replacement_version(name, pinned, lock_versions)
        if replacement is None:
            continue
        if replacement == DROP_SKIP:
            drops.append(spec)
        else:
            updates.append((name, pinned, replacement))

    if not updates and not drops:
        return False

    content = deny_path.read_text(encoding="utf-8")
    new_content = apply_skip_updates(content, updates)
    new_content = apply_skip_drops(new_content, drops)
    if check:
        return new_content != content

    deny_path.write_text(new_content, encoding="utf-8")
    return True


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Sync deny.toml [bans.skip] version pins with Cargo.lock"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when deny.toml skip pins are out of sync with Cargo.lock",
    )
    args = parser.parse_args()

    repo_root = get_repo_root()
    deny_path = repo_root / "deny.toml"
    lock_path = repo_root / "Cargo.lock"

    if not deny_path.exists():
        print(f"Error: {deny_path} not found", file=sys.stderr)
        return 1
    if not lock_path.exists():
        print(f"Error: {lock_path} not found", file=sys.stderr)
        return 1

    try:
        if args.check:
            if sync_deny_skips(deny_path, lock_path, check=True):
                msg = (
                    "Error: deny.toml bans.skip pins are out of sync with "
                    "Cargo.lock. Run: make sync-deny-skips"
                )
                print(msg, file=sys.stderr)
                return 1
            return 0

        changed = sync_deny_skips(deny_path, lock_path)
        if changed:
            print("Updated deny.toml bans.skip version pins from Cargo.lock")
        return 0
    except SyncDenySkipsError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
