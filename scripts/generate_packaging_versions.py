#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Update packaging spec files with version from Cargo.toml.

Single source of truth: Cargo.toml [workspace.package].version.
Run from repository root (PYTHONPATH=. so `scripts` imports resolve):
  PYTHONPATH=. python scripts/generate_packaging_versions.py

Updates:
  packaging/alpine/APKBUILD   pkgver=
  packaging/arch/PKGBUILD    pkgver=
  Cargo.toml                 [workspace.dependencies] vlz-* version=
  packaging/obs/rpm/verilyze.spec  cargo/rust BuildRequires (MSRV from
                             [workspace.package] rust-version)

RPM spec and Docker get version via Makefile at build time.
cargo-deb and cargo-aur read Cargo.toml directly.
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import cast

from scripts.rust_version import format_rust_version, read_msrv


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


def get_rust_version(cargo_toml: Path) -> str:
    """Return [workspace.package] rust-version (MSRV) as major.minor."""
    try:
        return format_rust_version(read_msrv(cargo_toml.parent))
    except ValueError as e:
        msg = f"Error: could not read rust-version from {cargo_toml}: {e}"
        raise SystemExit(msg) from e


_OBS_VERSIONED_REQUIRES = re.compile(
    r"^(BuildRequires:\s+(?:cargo|rust))\d+\.\d+\s*$", re.MULTILINE
)
_OBS_MINIMUM_REQUIRES = re.compile(
    r"^(BuildRequires:\s+(?:cargo|rust)\s+>=\s+)\d+\.\d+\.\d+\s*$",
    re.MULTILINE,
)


def update_obs_spec_msrv(content: str, msrv: str) -> str:
    """Set cargo/rust BuildRequires in the OBS RPM spec to the MSRV."""
    content = _OBS_VERSIONED_REQUIRES.sub(rf"\g<1>{msrv}", content)
    return _OBS_MINIMUM_REQUIRES.sub(rf"\g<1>{msrv}.0", content)


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


def update_workspace_internal_dep_versions(content: str, version: str) -> str:
    """Set version = \"<version>\" on internal vlz-* workspace dependencies."""
    lines: list[str] = []
    for line in content.splitlines():
        if re.match(r"^vlz-", line) and "version" in line:
            line = re.sub(
                r'version = "[^"]*"',
                f'version = "{version}"',
                line,
            )
        lines.append(line)
    return "\n".join(lines) + "\n"


# pylint: disable-next=too-many-locals,too-many-return-statements
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
    obs_spec_path = repo_root / "packaging" / "obs" / "rpm" / "verilyze.spec"

    if not cargo_toml.exists():
        print(f"Error: {cargo_toml} not found", file=sys.stderr)
        return 1
    if not apkbuild_path.exists():
        print(f"Error: {apkbuild_path} not found", file=sys.stderr)
        return 1
    if not pkgbuild_path.exists():
        print(f"Error: {pkgbuild_path} not found", file=sys.stderr)
        return 1

    if not obs_spec_path.exists():
        print(f"Error: {obs_spec_path} not found", file=sys.stderr)
        return 1

    version = get_version(cargo_toml)
    msrv = get_rust_version(cargo_toml)
    cargo_content = cargo_toml.read_text(encoding="utf-8")
    apkbuild_content = apkbuild_path.read_text(encoding="utf-8")
    pkgbuild_content = pkgbuild_path.read_text(encoding="utf-8")
    obs_spec_content = obs_spec_path.read_text(encoding="utf-8")

    new_cargo = update_workspace_internal_dep_versions(cargo_content, version)
    new_apkbuild = update_apkbuild(apkbuild_content, version)
    new_pkgbuild = update_pkgbuild(pkgbuild_content, version)
    new_obs_spec = update_obs_spec_msrv(obs_spec_content, msrv)

    if args.check:
        out_of_sync = (
            cargo_content != new_cargo
            or apkbuild_content != new_apkbuild
            or pkgbuild_content != new_pkgbuild
            or obs_spec_content != new_obs_spec
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
    cargo_toml.write_text(new_cargo, encoding="utf-8")
    obs_spec_path.write_text(new_obs_spec, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
