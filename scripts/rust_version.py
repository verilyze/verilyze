#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and compare Rust versions (MSRV and dev toolchain) from the repo.

`[workspace.package].rust-version` in Cargo.toml is the MSRV and the single
source for packaging gates. `rust-toolchain.toml` pins the dev/CI toolchain,
which may lead the MSRV but must never trail it.
"""

from pathlib import Path
import re
import tomllib

RustVersion = tuple[int, int]

_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?$")


def parse_rust_version(text: str) -> RustVersion:
    """Return (major, minor) from `1.98` or `1.98.1` style text."""
    match = _VERSION_PATTERN.match(text.strip())
    if not match:
        msg = f"not a numeric Rust version: {text!r}"
        raise ValueError(msg)
    return (int(match.group(1)), int(match.group(2)))


def format_rust_version(version: RustVersion) -> str:
    """Format (major, minor) as `major.minor`."""
    return f"{version[0]}.{version[1]}"


def read_msrv(repo_root: Path) -> RustVersion:
    """Return the workspace MSRV from Cargo.toml `rust-version`."""
    data = tomllib.loads(
        (repo_root / "Cargo.toml").read_text(encoding="utf-8")
    )
    package = data.get("workspace", {}).get("package", {})
    value = package.get("rust-version") if isinstance(package, dict) else None
    if not isinstance(value, str):
        msg = "workspace.package.rust-version is missing in Cargo.toml"
        raise ValueError(msg)
    return parse_rust_version(value)


def read_toolchain_channel(repo_root: Path) -> str | None:
    """Return the `rust-toolchain.toml` channel, or None when absent."""
    path = repo_root / "rust-toolchain.toml"
    if not path.is_file():
        return None
    toolchain = tomllib.loads(path.read_text(encoding="utf-8"))
    channel = toolchain.get("toolchain", {}).get("channel")
    return channel if isinstance(channel, str) else None
