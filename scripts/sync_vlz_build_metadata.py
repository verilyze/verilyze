#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Sync vlz build-metadata.toml from pyproject.toml."""

import argparse
import sys
import textwrap
import tomllib
from pathlib import Path

_DEFAULT_COPYRIGHT = "The verilyze contributors"
_DEFAULT_LICENSE = "GPL-3.0-or-later"
# REUSE-IgnoreStart -- tags used only when writing generated TOML
_SPDX_COPYRIGHT_TAG = "SPDX-FileCopyrightText"
_SPDX_LICENSE_TAG = "SPDX-License-Identifier"
# REUSE-IgnoreEnd


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def _spdx_header(copyright_holder: str, license_id: str) -> str:
    """Render SPDX header for generated build-metadata.toml."""
    return (
        f"# {_SPDX_COPYRIGHT_TAG}: 2026 {copyright_holder}\n"
        "#\n"
        f"# {_SPDX_LICENSE_TAG}: {license_id}\n"
        "\n"
        "# Crate-local build constants (mirrors pyproject.toml "
        "[tool.verilyze]).\n"
        "# Regenerate from repo root via: make sync-vlz-crate-assets\n"
    )


def render_build_metadata(pyproject: Path) -> str:
    """Render build-metadata.toml content from pyproject.toml."""
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)
    tool = data.get("tool", {})
    verilyze = tool.get("verilyze", {}) if isinstance(tool, dict) else {}
    headers = tool.get("vlz-headers", {}) if isinstance(tool, dict) else {}
    if isinstance(verilyze, dict):
        line_length = verilyze.get("line-length", 79)
    else:
        line_length = 79
    if isinstance(headers, dict):
        spdx_copyright = headers.get("default_copyright", _DEFAULT_COPYRIGHT)
        license_id = headers.get("default_license", _DEFAULT_LICENSE)
    else:
        spdx_copyright = _DEFAULT_COPYRIGHT
        license_id = _DEFAULT_LICENSE
    header = _spdx_header(str(spdx_copyright), str(license_id))
    body = textwrap.dedent(f"""\
        [tool.verilyze]
        line-length = {int(line_length)}

        [tool.vlz-headers]
        default_copyright = {spdx_copyright!r}
        default_license = {license_id!r}
        """)
    return f"{header}\n{body}"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify build-metadata.toml matches pyproject.toml",
    )
    args = parser.parse_args(argv)
    repo_root = get_repo_root()
    pyproject = repo_root / "pyproject.toml"
    output = repo_root / "crates" / "core" / "vlz" / "build-metadata.toml"
    expected = render_build_metadata(pyproject)
    if args.check:
        current = (
            output.read_text(encoding="utf-8") if output.is_file() else ""
        )
        if current != expected:
            print(
                "error: build-metadata.toml is out of sync; "
                "run make sync-vlz-crate-assets",
                file=sys.stderr,
            )
            return 1
        return 0
    output.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
