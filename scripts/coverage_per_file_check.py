#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fail when any production scripts/*.py module is below the line threshold."""

import argparse
import sys
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path

DEFAULT_THRESHOLD = 95
SCRIPTS_PREFIX = "scripts/"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the per-file coverage checker."""
    parser = argparse.ArgumentParser(
        description="Verify per-file Python coverage from Cobertura XML.",
    )
    parser.add_argument(
        "cobertura_xml",
        type=Path,
        help="Path to cobertura-python.xml",
    )
    parser.add_argument(
        "--min-line-rate",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=(
            "Minimum line-rate percent per module "
            f"(default: {DEFAULT_THRESHOLD})"
        ),
    )
    return parser.parse_args(argv)


def _normalize_script_filename(filename: str) -> str | None:
    """Return canonical scripts/*.py path, or None when not a script module."""
    if not filename.endswith(".py"):
        return None
    if filename.startswith(SCRIPTS_PREFIX):
        return filename
    if "/" not in filename and "\\" not in filename:
        return f"{SCRIPTS_PREFIX}{filename}"
    return None


def production_script_classes(root: ET.Element) -> dict[str, float]:
    """Map scripts/*.py class names to line-rate percent."""
    rates: dict[str, float] = {}
    for package in root.findall(".//package"):
        for cls in package.findall("classes/class"):
            filename = cls.get("filename", "")
            script_name = _normalize_script_filename(filename)
            if script_name is None:
                continue
            if script_name == "scripts/coverage_per_file_check.py":
                continue
            line_rate = float(cls.get("line-rate", "0")) * 100.0
            rates[script_name] = line_rate
    return rates


def check_per_file_coverage(
    cobertura_xml: Path,
    *,
    min_line_rate: float = DEFAULT_THRESHOLD,
) -> list[str]:
    """Return error messages for modules below ``min_line_rate``."""
    if not cobertura_xml.is_file():
        msg = f"coverage XML not found: {cobertura_xml}"
        return [msg]

    root = ET.parse(cobertura_xml).getroot()  # nosec B314
    rates = production_script_classes(root)
    if not rates:
        return ["no scripts/*.py classes found in coverage XML"]

    errors: list[str] = []
    for filename in sorted(rates):
        rate = rates[filename]
        if rate + 1e-9 < min_line_rate:
            errors.append(
                f"{filename}: line coverage {rate:.2f}% "
                f"below {min_line_rate:.0f}%"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    """Run the per-file coverage check and return an exit code."""
    args = parse_args(argv)
    errors = check_per_file_coverage(
        args.cobertura_xml,
        min_line_rate=args.min_line_rate,
    )
    if errors:
        for message in errors:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
