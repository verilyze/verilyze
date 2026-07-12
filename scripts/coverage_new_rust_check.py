#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fail when newly added Rust files are below ship-pr coverage thresholds."""

import argparse
import subprocess  # nosec B404
import sys
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path

NEW_RUST_MIN_LINE_RATE = 95
NEW_RUST_MIN_FUNCTION_RATE = 90
NEW_RUST_MIN_REGION_RATE = 95

_DEFAULT_COBERTURA = Path("reports/cobertura-rust.xml")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the new-Rust-file coverage checker."""
    parser = argparse.ArgumentParser(
        description=(
            "Verify per-file Rust coverage for newly added .rs files "
            "from Cobertura XML (ship-pr gate; not part of make check)."
        ),
    )
    parser.add_argument(
        "cobertura_xml",
        type=Path,
        nargs="?",
        default=_DEFAULT_COBERTURA,
        help=f"Path to cobertura-rust.xml (default: {_DEFAULT_COBERTURA})",
    )
    parser.add_argument(
        "--file",
        action="append",
        dest="files",
        default=[],
        metavar="PATH",
        help="Repo-relative .rs path to check (repeatable)",
    )
    parser.add_argument(
        "--git-base",
        default="",
        help=(
            "Discover added .rs files via "
            "git diff --diff-filter=A --name-only BASE...HEAD"
        ),
    )
    parser.add_argument(
        "--min-line-rate",
        type=float,
        default=NEW_RUST_MIN_LINE_RATE,
        help=f"Minimum line-rate percent (default: {NEW_RUST_MIN_LINE_RATE})",
    )
    parser.add_argument(
        "--min-function-rate",
        type=float,
        default=NEW_RUST_MIN_FUNCTION_RATE,
        help=(
            "Minimum function-rate percent "
            f"(default: {NEW_RUST_MIN_FUNCTION_RATE})"
        ),
    )
    parser.add_argument(
        "--min-region-rate",
        type=float,
        default=NEW_RUST_MIN_REGION_RATE,
        help=(
            "Minimum region-rate percent "
            f"(default: {NEW_RUST_MIN_REGION_RATE})"
        ),
    )
    return parser.parse_args(argv)


def normalize_rust_path(filename: str, target: str) -> str | None:
    """Return ``target`` when ``filename`` refers to the same .rs file."""
    if not target.endswith(".rs") or not filename.endswith(".rs"):
        return None
    norm_target = target.replace("\\", "/").lstrip("./")
    norm_name = filename.replace("\\", "/").lstrip("./")
    if norm_name == norm_target or norm_name.endswith("/" + norm_target):
        return norm_target
    return None


def _method_function_rate(cls: ET.Element) -> float | None:
    rates: list[float] = []
    for method in cls.findall("methods/method"):
        raw = method.get("line-rate")
        if raw is not None:
            rates.append(float(raw) * 100.0)
    if not rates:
        return None
    return sum(rates) / len(rates)


def rust_file_rates(root: ET.Element) -> dict[str, dict[str, float]]:
    """Map repo-relative ``*.rs`` paths to line/function/region percents."""
    rates: dict[str, dict[str, float]] = {}
    for package in root.findall(".//package"):
        for cls in package.findall("classes/class"):
            filename = cls.get("filename", "").replace("\\", "/")
            if not filename.endswith(".rs"):
                continue
            line_rate = float(cls.get("line-rate", "0")) * 100.0
            region_rate = float(cls.get("branch-rate", "0")) * 100.0
            function_rate = _method_function_rate(cls)
            if function_rate is None:
                function_rate = line_rate
            rates[filename.lstrip("./")] = {
                "line": line_rate,
                "function": function_rate,
                "region": region_rate,
            }
    return rates


def discover_added_rust_files(git_base: str) -> list[str]:
    """Return added ``*.rs`` paths from ``git diff --diff-filter=A``."""
    base = git_base.strip()
    if not base:
        return []
    proc = subprocess.run(  # nosec B603 B607
        [
            "git",
            "diff",
            "--diff-filter=A",
            "--name-only",
            f"{base}...HEAD",
            "--",
            "*.rs",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or "git diff failed"
        raise RuntimeError(msg)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _lookup_file_rates(
    rates: dict[str, dict[str, float]],
    target: str,
) -> dict[str, float] | None:
    for key, value in rates.items():
        if normalize_rust_path(key, target) == target:
            return value
    return None


def _threshold_errors(
    target: str,
    matched: dict[str, float],
    *,
    min_line_rate: float,
    min_function_rate: float,
    min_region_rate: float,
) -> list[str]:
    errors: list[str] = []
    checks = (
        ("line", min_line_rate, "line coverage"),
        ("function", min_function_rate, "function coverage"),
        ("region", min_region_rate, "region coverage"),
    )
    for key, minimum, label in checks:
        rate = matched[key]
        if rate + 1e-9 < minimum:
            errors.append(
                f"{target}: {label} {rate:.2f}% below {minimum:.0f}%"
            )
    return errors


def check_new_rust_coverage(
    cobertura_xml: Path,
    files: list[str],
    *,
    min_line_rate: float = NEW_RUST_MIN_LINE_RATE,
    min_function_rate: float = NEW_RUST_MIN_FUNCTION_RATE,
    min_region_rate: float = NEW_RUST_MIN_REGION_RATE,
) -> list[str]:
    """Return error messages for new files below thresholds."""
    normalized = [p.replace("\\", "/").lstrip("./") for p in files if p]
    if not normalized:
        return []

    if not cobertura_xml.is_file():
        msg = f"coverage XML not found: {cobertura_xml}"
        return [msg]

    root = ET.parse(cobertura_xml).getroot()  # nosec B314
    rates = rust_file_rates(root)
    if not rates:
        return ["no Rust .rs classes found in coverage XML"]

    errors: list[str] = []
    for target in sorted(normalized):
        matched = _lookup_file_rates(rates, target)
        if matched is None:
            errors.append(f"{target}: not found in coverage XML")
            continue
        errors.extend(
            _threshold_errors(
                target,
                matched,
                min_line_rate=min_line_rate,
                min_function_rate=min_function_rate,
                min_region_rate=min_region_rate,
            )
        )
    return errors


def _normalize_file_paths(files: list[str]) -> list[str]:
    return list(
        dict.fromkeys(f.replace("\\", "/").lstrip("./") for f in files)
    )


def main(argv: list[str] | None = None) -> int:
    """Run the new-Rust-file coverage check and return an exit code."""
    args = parse_args(argv)
    files = list(args.files)
    if args.git_base:
        try:
            files.extend(discover_added_rust_files(args.git_base))
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    errors = check_new_rust_coverage(
        args.cobertura_xml,
        _normalize_file_paths(files),
        min_line_rate=args.min_line_rate,
        min_function_rate=args.min_function_rate,
        min_region_rate=args.min_region_rate,
    )
    if not errors:
        return 0
    for message in errors:
        print(f"ERROR: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
