#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=duplicate-code  # extract returns list for exact-duplicate detection

"""
Check for duplicate copyright holders in REUSE-compliant file headers.

Uses .mailmap as the source of truth: two identifiers that map to the same
canonical identity are duplicates. Two people with the same name but different
emails are distinct unless .mailmap says otherwise.

Exit 0 when no duplicates; exit 1 when duplicates found.
Run from repository root: python scripts/check_header_duplicates.py
"""

import re
import sys
from pathlib import Path

from scripts.update_headers import load_config, collect_files


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def parse_mailmap(repo_root: Path) -> dict[str, str]:
    """
    Parse .mailmap: alternate identity -> canonical identity.

    Format: Canonical Name <canonical@email.com> Alternate Name <alt@email.com>
    """
    mailmap_path = repo_root / ".mailmap"
    if not mailmap_path.exists():
        return {}
    result: dict[str, str] = {}
    pattern = re.compile(r"^([^<]+<[^>]+>)\s+(.+)$")
    for line in mailmap_path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            canonical = match.group(1).strip()
            alternate = match.group(2).strip()
            if canonical and alternate:
                result[alternate] = canonical
    return result


def extract_copyright_identifiers(header: str) -> list[str]:
    """
    Extract "Name <email>" from SPDX-FileCopyrightText lines.

    Returns a list (preserves duplicates for exact-duplicate-line detection).
    """
    ids: list[str] = []
    for line in header.splitlines():
        if "SPDX-FileCopyrightText" not in line:
            continue
        match = re.search(r"SPDX-FileCopyrightText:\s*(.+)", line)
        if match:
            content = match.group(1).strip()
            parts = content.split(None, 1)
            if len(parts) >= 2:
                ids.append(parts[1])
    return ids


def _get_header_path(repo_root: Path, file_path: str) -> Path:
    """Return path to header (file or file.license for force-dot-license)."""
    full = repo_root / file_path
    license_file = Path(str(full) + ".license")
    if license_file.exists():
        return license_file
    return full


def _get_header_content(path: Path) -> str:
    """Read header portion of file (first 2000 chars)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return ""


def collect_covered_files(repo_root: Path) -> list[str]:
    """
    Return REUSE-covered files (same logic as update_headers.collect_files).
    """
    config = load_config(repo_root)
    return collect_files(repo_root, config)


def get_files_with_duplicates(repo_root: Path) -> list[tuple[str, list[str]]]:
    """
    Return list of (file_path, [duplicate_holder_identifiers]) for files
    that have duplicate copyright holders per .mailmap canonicalization.
    """
    mailmap = parse_mailmap(repo_root)
    files = collect_covered_files(repo_root)
    duplicates: list[tuple[str, list[str]]] = []

    for file_path in files:
        header_path = _get_header_path(repo_root, file_path)
        if not header_path.exists():
            continue
        header = _get_header_content(header_path)
        if "SPDX-FileCopyrightText" not in header:
            continue

        idents = extract_copyright_identifiers(header)
        if not idents:
            continue

        canon_to_idents: dict[str, list[str]] = {}
        for ident in idents:
            canon = mailmap.get(ident, ident)
            canon_to_idents.setdefault(canon, []).append(ident)

        for canon, ident_list in canon_to_idents.items():
            if len(ident_list) > 1:
                duplicates.append((file_path, ident_list))
                break

    return duplicates


def main() -> int:
    """
    Main entry point. Returns 0 when no duplicates, 1 when duplicates found.
    """
    repo_root = get_repo_root()
    duplicates = get_files_with_duplicates(repo_root)
    if duplicates:
        for file_path, holders in duplicates:
            holders_str = ", ".join(sorted(set(holders)))
            msg = f"{file_path}: duplicate copyright holders: {holders_str}"
            print(msg, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
