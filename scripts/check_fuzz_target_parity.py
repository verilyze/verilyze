#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Assert AFL and cargo-fuzz fuzz target basenames stay in sync.

AFL bins live in tests/fuzz/Cargo.toml ([[bin]] name = ...).
ClusterFuzzLite / cargo-fuzz targets are fuzz/fuzz_targets/<name>.rs.
"""

import argparse
import re
import sys
from pathlib import Path

_BIN_NAME_RE = re.compile(
    r"^\[\[bin\]\]\s*\n(?:(?!\[\[).*\n)*?name\s*=\s*\"([^\"]+)\"",
    re.MULTILINE,
)


def afl_bin_names(cargo_toml: Path) -> set[str]:
    """Return [[bin]] name values from an AFL fuzz Cargo.toml."""
    text = cargo_toml.read_text(encoding="utf-8")
    names = set(_BIN_NAME_RE.findall(text))
    if not names:
        raise ValueError(f"no [[bin]] name entries in {cargo_toml}")
    return names


def cargo_fuzz_target_names(targets_dir: Path) -> set[str]:
    """Return basenames of *.rs files under a cargo-fuzz fuzz_targets dir."""
    if not targets_dir.is_dir():
        raise ValueError(f"missing cargo-fuzz targets dir: {targets_dir}")
    names = {p.stem for p in targets_dir.glob("*.rs") if p.is_file()}
    if not names:
        raise ValueError(f"no *.rs fuzz targets in {targets_dir}")
    return names


def parity_errors(afl: set[str], cargo_fuzz: set[str]) -> list[str]:
    """Return human-readable errors when AFL and cargo-fuzz names differ."""
    errors: list[str] = []
    for name in sorted(afl - cargo_fuzz):
        errors.append(
            f"AFL target {name!r} missing from cargo-fuzz "
            f"(expected fuzz/fuzz_targets/{name}.rs)"
        )
    for name in sorted(cargo_fuzz - afl):
        errors.append(
            f"cargo-fuzz target {name!r} missing from AFL "
            f"(expected [[bin]] name in tests/fuzz/Cargo.toml)"
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    """Compare AFL and cargo-fuzz target names; return process exit code."""
    parser = argparse.ArgumentParser(
        description="Check AFL and cargo-fuzz fuzz target name parity",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root (default: parent of scripts/)",
    )
    args = parser.parse_args(argv)
    root = args.root
    if root is None:
        root = Path(__file__).resolve().parent.parent

    afl_cargo = root / "tests" / "fuzz" / "Cargo.toml"
    cfl_targets = root / "fuzz" / "fuzz_targets"

    try:
        afl = afl_bin_names(afl_cargo)
        cfl = cargo_fuzz_target_names(cfl_targets)
    except (OSError, ValueError) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    errors = parity_errors(afl, cfl)
    if errors:
        print(
            "ERROR: AFL and cargo-fuzz fuzz targets are out of sync:",
            file=sys.stderr,
        )
        for msg in errors:
            print(f"  - {msg}", file=sys.stderr)
        return 1

    print(f"OK: {len(afl)} AFL and cargo-fuzz fuzz targets match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
