#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=duplicate-code  # CLI --check/main shape mirrors upload_sarif_pins

"""Refresh Cloud Agent Dockerfile rustup-init SHA-256 pins from the archive.

Renovate bumps ARG RUSTUP_VERSION in .cursor/Dockerfile via a regex manager.
This helper fetches the matching amd64/arm64 rustup-init.sha256 digests from
static.rust-lang.org and updates ARG RUSTUP_INIT_SHA256_{AMD64,ARM64} so
post-upgrade PRs never leave checksums stale (Scorecard / build integrity).
"""

import argparse
import re
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

DOCKERFILE_REL = Path(".cursor/Dockerfile")

_VERSION_RE = re.compile(
    r"^ARG RUSTUP_VERSION=(?P<version>\d+\.\d+\.\d+)\s*$",
    re.MULTILINE,
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_AMD64_ARG_RE = re.compile(
    r"^(ARG RUSTUP_INIT_SHA256_AMD64=)[0-9a-f]{64}",
    re.MULTILINE,
)
_ARM64_ARG_RE = re.compile(
    r"^(ARG RUSTUP_INIT_SHA256_ARM64=)[0-9a-f]{64}",
    re.MULTILINE,
)

_TRIPLES = {
    "amd64": "x86_64-unknown-linux-gnu",
    "arm64": "aarch64-unknown-linux-gnu",
}

_ARCHIVE_SHA256_URL = (
    "https://static.rust-lang.org/rustup/archive/"
    "{version}/{triple}/rustup-init.sha256"
)

FetchFn = Callable[..., str]


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def parse_rustup_version(dockerfile_text: str) -> str:
    """Return ARG RUSTUP_VERSION from Dockerfile text."""
    match = _VERSION_RE.search(dockerfile_text)
    if match is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG RUSTUP_VERSION=<semver> pin"
        )
    return match.group("version")


def replace_sha256_args(
    dockerfile_text: str, *, amd64: str, arm64: str
) -> str:
    """Return Dockerfile text with both rustup-init SHA-256 ARGs replaced."""
    for label, digest in (("amd64", amd64), ("arm64", arm64)):
        if not _SHA256_RE.fullmatch(digest):
            raise SystemExit(f"invalid SHA-256 digest for {label}: {digest!r}")

    if _AMD64_ARG_RE.search(dockerfile_text) is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG RUSTUP_INIT_SHA256_AMD64 pin"
        )
    if _ARM64_ARG_RE.search(dockerfile_text) is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG RUSTUP_INIT_SHA256_ARM64 pin"
        )

    updated = _AMD64_ARG_RE.sub(
        rf"\g<1>{amd64}",
        dockerfile_text,
        count=1,
    )
    return _ARM64_ARG_RE.sub(
        rf"\g<1>{arm64}",
        updated,
        count=1,
    )


def fetch_archive_sha256(
    version: str,
    triple: str,
    *,
    opener: Callable[..., Any] | None = None,
    timeout: float = 30,
) -> str:
    """Fetch rustup-init.sha256 for version/triple from the archive."""
    url = _ARCHIVE_SHA256_URL.format(version=version, triple=triple)
    open_url = opener or urllib.request.urlopen
    with open_url(url, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    digest = body.split()[0] if body.strip() else ""
    if not _SHA256_RE.fullmatch(digest):
        raise SystemExit(f"malformed checksum from {url}: {body!r}")
    return digest


def sync_dockerfile_sha256s(
    repo_root: Path,
    *,
    fetch: FetchFn | None = None,
    check: bool = False,
) -> bool:
    """
    Align .cursor/Dockerfile SHA-256 ARGs with the archive for RUSTUP_VERSION.

    Returns True when the file would change (or differs in check mode).
    """
    path = repo_root / DOCKERFILE_REL
    if not path.is_file():
        raise SystemExit(f"Dockerfile not found: {path}")

    fetch_fn = fetch if fetch is not None else fetch_archive_sha256
    text = path.read_text(encoding="utf-8")
    version = parse_rustup_version(text)
    amd64 = fetch_fn(version, _TRIPLES["amd64"])
    arm64 = fetch_fn(version, _TRIPLES["arm64"])
    updated = replace_sha256_args(text, amd64=amd64, arm64=arm64)

    if updated == text:
        return False

    if check:
        return True

    path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    """CLI entry point for Renovate post-upgrade and local --check."""
    parser = argparse.ArgumentParser(
        description=(
            "Refresh .cursor/Dockerfile rustup-init SHA-256 ARGs from "
            "static.rust-lang.org for the pinned RUSTUP_VERSION"
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when Dockerfile SHA-256 ARGs do not match the archive",
    )
    args = parser.parse_args()

    drift = sync_dockerfile_sha256s(get_repo_root(), check=args.check)
    if args.check and drift:
        print(
            f"Error: {DOCKERFILE_REL} rustup-init SHA-256 ARGs are out of "
            "sync with static.rust-lang.org for ARG RUSTUP_VERSION. "
            "Run: PYTHONPATH=. python3 scripts/rustup_init_pins.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
