#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Require full-semver trailing comments on GitHub Actions digest pins.

Zizmor ref-version-mismatch treats major-only comments (# v2) as moving refs.
Digest pins must use the exact release tag (# v2.9.2) so nightly
super-linter-full stays stable when newer tags appear. See CONTRIBUTING
Renovate / super-linter section.

Actions whose upstream publishes only a moving major tag (ClusterFuzzLite)
require that tag instead (# v1). Renovate resolves digests against the real
tag, so a missing or invented tag comment stops automatic digest bumps.

Scans digest-pinned uses: lines under .github/workflows/ and examples/.
Skips reusable workflow refs (action path contains /.github/workflows/)
and non-SHA refs.
"""

import argparse
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

# Shared with tests: exact release tag form for digest pin comments.
FULL_SEMVER_TAG_RE = re.compile(r"v\d+\.\d+\.\d+")

# Tag form for actions that publish no full-semver release tag.
MAJOR_TAG_RE = re.compile(r"v\d+")

# ClusterFuzzLite ships a moving v1 tag only; pins carry # v1 plus
# # zizmor: ignore[ref-version-mismatch].
MOVING_MAJOR_TAG_ACTION_PREFIXES = ("google/clusterfuzzlite/",)

_DIGEST_SHA = r"[a-f0-9]{40}"
_USES_DIGEST_RE = re.compile(
    rf"^(\s*)(?:-\s+)?uses:\s+"
    rf"(?P<action>\S+)@(?P<sha>{_DIGEST_SHA})"
    rf"(?P<tail>.*)$"
)

_WORKFLOW_GLOB = ".github/workflows/*.yml"
_EXAMPLE_GLOB = "examples/**/*.yml"


@dataclass(frozen=True, slots=True)
class PinCommentFinding:
    """One digest pin with a missing or imprecise version comment."""

    path: str
    line: int
    message: str


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def _version_token(comment: str | None) -> str | None:
    """Return the leading version token from a uses: trailing comment."""
    if comment is None:
        return None
    # Allow "# v3.0.2  # zizmor: ignore[...]" -- first segment is the tag.
    first = comment.split("#", 1)[0].strip()
    return first or None


def _comment_from_tail(tail: str) -> str | None:
    """Return YAML comment text after the digest pin, or None if absent."""
    stripped = tail.strip()
    if not stripped.startswith("#"):
        return None
    body = stripped[1:].strip()
    return body or None


def _tag_requirement(action: str) -> tuple[re.Pattern[str], str]:
    """Return the allowed tag pattern and its hint for one action."""
    if action.startswith(MOVING_MAJOR_TAG_ACTION_PREFIXES):
        return MAJOR_TAG_RE, "# vN"
    return FULL_SEMVER_TAG_RE, "# vX.Y.Z"


def find_pin_comment_issues(
    text: str, *, path: str
) -> list[PinCommentFinding]:
    """Return findings for digest-pinned step uses: lines in workflow text."""
    findings: list[PinCommentFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        match = _USES_DIGEST_RE.match(line)
        if match is None:
            continue
        action = match.group("action")
        # Reusable workflow refs; comment policy differs (zizmor ignore).
        if "/.github/workflows/" in action:
            continue
        allowed, hint = _tag_requirement(action)
        token = _version_token(_comment_from_tail(match.group("tail")))
        if token is None:
            findings.append(
                PinCommentFinding(
                    path=path,
                    line=line_no,
                    message=(
                        f"missing release tag comment ({hint}) "
                        f"on digest pin for {action}"
                    ),
                )
            )
            continue
        if allowed.fullmatch(token) is None:
            findings.append(
                PinCommentFinding(
                    path=path,
                    line=line_no,
                    message=(
                        f"version comment {token!r} must be the upstream "
                        f"release tag ({hint}) for {action}"
                    ),
                )
            )
    return findings


def _iter_scan_paths(repo_root: Path) -> Iterable[Path]:
    yield from sorted(repo_root.glob(_WORKFLOW_GLOB))
    yield from sorted(repo_root.glob(_EXAMPLE_GLOB))


def check_pin_comments(repo_root: Path) -> list[PinCommentFinding]:
    """Scan workflow and example YAML for imprecise digest pin comments."""
    findings: list[PinCommentFinding] = []
    for path in _iter_scan_paths(repo_root):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8")
        findings.extend(find_pin_comment_issues(text, path=rel))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "Fail when GitHub Actions digest pins lack a full-semver "
            "trailing comment (# vX.Y.Z)"
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when any pin comment is missing or not full semver",
    )
    args = parser.parse_args(argv)

    if not args.check:
        parser.error("--check is required")

    findings = check_pin_comments(get_repo_root())
    if not findings:
        return 0

    for finding in findings:
        print(
            f"{finding.path}:{finding.line}: {finding.message}",
            file=sys.stderr,
        )
    print(
        "Error: GitHub Actions digest pins must use a full-semver trailing "
        "comment (# vX.Y.Z), not major-only (# v2). Actions that publish "
        "only a moving major tag (ClusterFuzzLite) use that tag (# v1). "
        "See CONTRIBUTING Renovate / super-linter section.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
