#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Sync upload-sarif digest pins from supply-chain.yml to the CI example workflow.

Canonical source: .github/workflows/supply-chain.yml (Renovate github-actions
manager updates workflows; post-upgrade hook and make targets keep the example
aligned). See CONTRIBUTING Renovate section and NFR-014.
"""

import argparse
import re
import sys
from pathlib import Path

SUPPLY_CHAIN_WORKFLOW = Path(".github/workflows/supply-chain.yml")
EXAMPLE_WORKFLOW = Path("examples/github-action-vlz-scan.yml")

UPLOAD_SARIF_REF_RE = re.compile(
    r"github/codeql-action/upload-sarif@[a-f0-9]{40}"
)
UPLOAD_SARIF_USES_RE = re.compile(
    r"uses: github/codeql-action/upload-sarif@[a-f0-9]{40}(?:\s+# v[^\n]+)?"
)


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def canonical_ref(supply_chain_text: str) -> str:
    """Return the first upload-sarif ref from supply-chain workflow text."""
    match = UPLOAD_SARIF_REF_RE.search(supply_chain_text)
    if match is None:
        raise SystemExit("supply-chain workflow missing upload-sarif pin")
    return match.group(0)


def canonical_uses_line(supply_chain_text: str) -> str:
    """Return the first upload-sarif uses line (no leading whitespace)."""
    match = UPLOAD_SARIF_USES_RE.search(supply_chain_text)
    if match is None:
        raise SystemExit(
            "supply-chain workflow missing upload-sarif uses line"
        )
    return match.group(0)


def _replace_example_pins(example_text: str, canonical_line: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        indent = match.group(1)
        return f"{indent}{canonical_line}"

    pattern = re.compile(
        r"^(\s*)uses: github/codeql-action/upload-sarif@[a-f0-9]{40}"
        r"(?:\s+# v[^\n]+)?",
        re.MULTILINE,
    )
    return pattern.sub(replacer, example_text)


def sync_example(repo_root: Path, *, check: bool = False) -> bool:
    """
    Copy the canonical upload-sarif pin from supply-chain.yml into the example.

    Returns True when the example file would change or is out of sync in check
    mode. In check mode, exits with status 1 when drift is detected.
    """
    supply_path = repo_root / SUPPLY_CHAIN_WORKFLOW
    example_path = repo_root / EXAMPLE_WORKFLOW

    if not supply_path.is_file():
        raise SystemExit(f"supply-chain workflow not found: {supply_path}")
    if not example_path.is_file():
        raise SystemExit(f"example workflow not found: {example_path}")

    supply_text = supply_path.read_text(encoding="utf-8")
    example_text = example_path.read_text(encoding="utf-8")
    canonical_line = canonical_uses_line(supply_text)
    updated_text = _replace_example_pins(example_text, canonical_line)

    if updated_text == example_text:
        return False

    if check:
        return True

    example_path.write_text(updated_text, encoding="utf-8")
    return True


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "Sync upload-sarif pins from supply-chain.yml to "
            "examples/github-action-vlz-scan.yml"
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the example pin differs from supply-chain.yml",
    )
    args = parser.parse_args()

    drift = sync_example(get_repo_root(), check=args.check)
    if args.check and drift:
        print(
            "Error: examples/github-action-vlz-scan.yml upload-sarif pin "
            "is out of sync with .github/workflows/supply-chain.yml. "
            "Run: make sync-upload-sarif-example",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
