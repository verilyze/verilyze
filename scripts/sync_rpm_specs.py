#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Synchronize local RPM spec content from the OBS RPM spec."""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path
import re
import sys

OBS_SPEC_PATH = Path("packaging/obs/rpm/verilyze.spec")
LOCAL_SPEC_PATH = Path("packaging/rpm/SPECS/verilyze.spec")

VERSION_PATTERN = re.compile(
    r"^Version:\s+([0-9]+\.[0-9]+\.[0-9]+)\s*$",
    re.MULTILINE,
)
PKG_NAME_LINE = "%global pkg_name verilyze\n"
LOCAL_VERSION_MACRO_TEMPLATE = "%{{!?version:%global version {version}}}\n"

# Explicit, frozen divergence points for Option A dual-spec maintenance.
OBS_ONLY_LINES = (
    "Source1:        vendor.tar.zst\n",
    "BuildRequires:  zstd\n",
    (
        "# Unpack OBS cargo_vendor tarball; it overlays .cargo, vendor/, and "
        "Cargo.lock.\n"
    ),
    "tar --zstd -xf %{SOURCE1}\n",
)

REPLACEMENTS = (
    ("Release:        0%{?dist}", "Release:        1%{?dist}"),
    (
        "Source0:        %{pkg_name}-%{version}.tar.xz",
        "Source0:        %{pkg_name}-%{version}.tar.gz",
    ),
    (
        "cargo build --release --locked --offline",
        "cargo build --release --locked",
    ),
)

LOCAL_INSERTION = (
    "# THIRD-PARTY-LICENSES is committed; see "
    "make generate-third-party-licenses\n"
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _extract_obs_version(obs_text: str) -> str:
    match = VERSION_PATTERN.search(obs_text)
    if not match:
        raise ValueError("Unable to parse OBS spec Version field.")
    return match.group(1)


def render_local_spec(obs_text: str) -> str:
    """Generate local RPM spec text from OBS spec text."""
    local_text = obs_text
    obs_version = _extract_obs_version(obs_text)

    local_text = VERSION_PATTERN.sub(
        "Version:        %{version}",
        local_text,
        count=1,
    )
    local_text = local_text.replace(
        PKG_NAME_LINE,
        PKG_NAME_LINE
        + LOCAL_VERSION_MACRO_TEMPLATE.format(version=obs_version),
        1,
    )

    for old, new in REPLACEMENTS:
        local_text = local_text.replace(old, new, 1)
    for line in OBS_ONLY_LINES:
        local_text = local_text.replace(line, "", 1)

    if LOCAL_INSERTION not in local_text and "\n%install\n" in local_text:
        local_text = local_text.replace(
            "\n%install\n",
            f"\n{LOCAL_INSERTION}\n%install\n",
            1,
        )

    return local_text


def _write_if_changed(path: Path, content: str) -> bool:
    existing = path.read_text(encoding="utf-8")
    if existing == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def _render_diff(expected: str, actual: str, path: Path) -> str:
    return "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"{path} (expected)",
            tofile=f"{path} (actual)",
        )
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Sync local RPM spec from OBS RPM spec."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate that local spec matches generated content.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run sync/check flow and return process exit code."""
    args = parse_args(argv)
    repo_root = _repo_root()
    obs_path = repo_root / OBS_SPEC_PATH
    local_path = repo_root / LOCAL_SPEC_PATH

    obs_text = obs_path.read_text(encoding="utf-8")
    expected_local = render_local_spec(obs_text)
    actual_local = local_path.read_text(encoding="utf-8")

    if args.check:
        if actual_local != expected_local:
            diff = _render_diff(expected_local, actual_local, LOCAL_SPEC_PATH)
            print(diff, file=sys.stderr, end="")
            return 1
        return 0

    changed = _write_if_changed(local_path, expected_local)
    if changed:
        print(f"Updated {LOCAL_SPEC_PATH}")
    else:
        print(f"No changes in {LOCAL_SPEC_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
