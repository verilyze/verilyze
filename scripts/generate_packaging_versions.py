#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Update packaging spec files with version from Cargo.toml.

Single source of truth: Cargo.toml [workspace.package].version.
Run from repository root:
  python scripts/generate_packaging_versions.py

Updates:
  packaging/alpine/APKBUILD   pkgver=
  packaging/arch/PKGBUILD    pkgver=

RPM spec and Docker get version via Makefile at build time.
cargo-deb and cargo-aur read Cargo.toml directly.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import cast


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def get_version(cargo_toml: Path) -> str:
    """Extract version from Cargo.toml [workspace.package]."""
    with open(cargo_toml, "rb") as f:
        data = tomllib.load(f)
    try:
        vers = data["workspace"]["package"]["version"]
        return cast(str, vers)
    except (KeyError, TypeError) as e:
        msg = f"Error: could not read version from {cargo_toml}: {e}"
        raise SystemExit(msg) from e


def update_apkbuild(content: str, version: str) -> str:
    """Replace pkgver= line in APKBUILD."""
    return re.sub(
        r"^pkgver=.*$",
        f"pkgver={version}",
        content,
        count=1,
        flags=re.MULTILINE,
    )


def update_pkgbuild(content: str, version: str) -> str:
    """Replace pkgver= line in PKGBUILD."""
    return re.sub(
        r"^pkgver=.*$",
        f"pkgver={version}",
        content,
        count=1,
        flags=re.MULTILINE,
    )


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Update packaging spec files with version from Cargo.toml"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify packaging files match; exit 1 if out of sync",
    )
    args = parser.parse_args()

    repo_root = get_repo_root()
    cargo_toml = repo_root / "Cargo.toml"
    apkbuild_path = repo_root / "packaging" / "alpine" / "APKBUILD"
    pkgbuild_path = repo_root / "packaging" / "arch" / "PKGBUILD"

    if not cargo_toml.exists():
        print(f"Error: {cargo_toml} not found", file=sys.stderr)
        return 1
    if not apkbuild_path.exists():
        print(f"Error: {apkbuild_path} not found", file=sys.stderr)
        return 1
    if not pkgbuild_path.exists():
        print(f"Error: {pkgbuild_path} not found", file=sys.stderr)
        return 1

    version = get_version(cargo_toml)
    apkbuild_content = apkbuild_path.read_text(encoding="utf-8")
    pkgbuild_content = pkgbuild_path.read_text(encoding="utf-8")

    new_apkbuild = update_apkbuild(apkbuild_content, version)
    new_pkgbuild = update_pkgbuild(pkgbuild_content, version)

    if args.check:
        out_of_sync = (
            apkbuild_content != new_apkbuild
            or pkgbuild_content != new_pkgbuild
        )
        if out_of_sync:
            msg = (
                "Error: packaging spec versions are out of sync with "
                "Cargo.toml. Run: make generate-packaging"
            )
            print(msg, file=sys.stderr)
            return 1
        return 0

    apkbuild_path.write_text(new_apkbuild, encoding="utf-8")
    pkgbuild_path.write_text(new_pkgbuild, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
