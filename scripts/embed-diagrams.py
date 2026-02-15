#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=invalid-name  # Script name uses hyphens for CLI convention

"""
Embed Mermaid diagrams from architecture/*.mmd into markdown files.

Replaces HTML comment markers:
  <!-- INCLUDE architecture/<name>.mmd -->
with fenced Mermaid code blocks containing the file contents.

Modes:
  default  - Update files in place
  --check  - Verify embedded content matches .mmd source; exit 1 if out of sync

Run from repository root:
  python scripts/embed-diagrams.py [--check] README.md ...
"""

import argparse
import re
import sys
from pathlib import Path


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def process_markdown(
    content: str,
    repo_root: Path,
) -> tuple[str, list[str]]:
    """
    Process markdown content, replacing INCLUDE markers with Mermaid blocks.

    Returns (processed_content, list of error messages).
    """
    errors: list[str] = []
    marker_re = re.compile(
        r"^\s*<!--\s*INCLUDE\s+(architecture/[a-zA-Z0-9_-]+\.mmd)\s*-->\s*$"
    )

    def replace_match(match: re.Match[str]) -> str:
        mmd_path = match.group(1)
        full_path = repo_root / mmd_path
        if not full_path.exists():
            errors.append(f"Missing file: {mmd_path}")
            return match.group(0)
        mmd_content = full_path.read_text(encoding="utf-8").rstrip()
        return "```mermaid\n" + mmd_content + "\n```\n"

    lines = content.splitlines(keepends=True)
    result_lines: list[str] = []

    for line in lines:
        mat = marker_re.match(line.rstrip("\n\r"))
        if mat:
            result_lines.append(replace_match(mat))
        else:
            result_lines.append(line)

    return "".join(result_lines), errors


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Embed Mermaid diagrams into markdown at INCLUDE markers"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify embedded content matches source; exit 1 if out of sync",
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Markdown files to process (e.g. README.md CONTRIBUTING.md)",
    )
    args = parser.parse_args()

    repo_root = get_repo_root()
    any_error = False
    any_mismatch = False

    for file_path in args.files:
        path = Path(file_path)
        if not path.is_absolute():
            path = repo_root / file_path

        if not path.exists():
            print(f"embed-diagrams: {path}: file not found", file=sys.stderr)
            any_error = True
            continue

        content = path.read_text(encoding="utf-8")
        processed, errors = process_markdown(content, repo_root)

        for err in errors:
            print(f"embed-diagrams: {err}", file=sys.stderr)
            any_error = True

        if args.check:
            if content != processed:
                msg = f"embed-diagrams: {path}: diagram content is out of sync"
                print(msg, file=sys.stderr)
                any_mismatch = True
        else:
            if not any_error:
                path.write_text(processed, encoding="utf-8")

    if any_error:
        return 2

    if args.check and any_mismatch:
        print(
            "Diagram content is out of sync with architecture/*.mmd.",
            file=sys.stderr,
        )
        print(
            "Run 'make update-doc-diagrams' and commit the changes.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
