#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=duplicate-code  # CLI --check/main shape mirrors rustup_init_pins

"""Refresh Cloud Agent Dockerfile Flutter / Dart SDK pins from upstream.

Renovate bumps ARG FLUTTER_VERSION in .cursor/Dockerfile via a regex manager.
This helper fetches the matching Linux stable archive path + SHA-256 and
bundled Dart SDK version from releases_linux.json, plus the Dart linux-arm64
checksum (Flutter does not publish a Linux arm64 archive), and updates
ARG FLUTTER_ARCHIVE_PATH, ARG FLUTTER_SHA256_AMD64, ARG DART_SDK_VERSION,
and ARG DART_SHA256_ARM64.
"""

import argparse
import json
import re
import sys
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DOCKERFILE_REL = Path(".cursor/Dockerfile")

_VERSION_RE = re.compile(
    r"^ARG FLUTTER_VERSION=(?P<version>\d+\.\d+\.\d+)\s*$",
    re.MULTILINE,
)
_DART_VERSION_TOKEN_RE = re.compile(r"\d+\.\d+\.\d+")
_DART_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ARCHIVE_PATH_RE = re.compile(
    r"^(?!.*\.\.)(?!/)[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)+$"
)
_FLUTTER_SHA_ARG_RE = re.compile(
    r"^(ARG FLUTTER_SHA256_AMD64=)[0-9a-f]{64}",
    re.MULTILINE,
)
_ARCHIVE_PATH_ARG_RE = re.compile(
    r"^(ARG FLUTTER_ARCHIVE_PATH=)\S+",
    re.MULTILINE,
)
_DART_VERSION_ARG_RE = re.compile(
    r"^(ARG DART_SDK_VERSION=)\d+\.\d+\.\d+",
    re.MULTILINE,
)
_DART_SHA_ARG_RE = re.compile(
    r"^(ARG DART_SHA256_ARM64=)[0-9a-f]{64}",
    re.MULTILINE,
)
_ARCHIVE_PATH_URL_RE = re.compile(
    r"flutter_infra_release/releases/\$\{FLUTTER_ARCHIVE_PATH\}"
)

_FLUTTER_RELEASES_URL = (
    "https://storage.googleapis.com/flutter_infra_release/releases/"
    "releases_linux.json"
)
_DART_ARM64_SHA256_URL = (
    "https://storage.googleapis.com/dart-archive/channels/stable/release/"
    "{version}/sdk/dartsdk-linux-arm64-release.zip.sha256sum"
)


@dataclass(frozen=True)
class FlutterReleasePins:
    """Pins derived from one Flutter Linux stable release entry."""

    flutter_sha256_amd64: str
    dart_sdk_version: str
    dart_sha256_arm64: str = ""
    archive_path: str = ""


FetchFlutterFn = Callable[..., FlutterReleasePins]
FetchDartFn = Callable[..., str]


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def parse_flutter_version(dockerfile_text: str) -> str:
    """Return ARG FLUTTER_VERSION from Dockerfile text."""
    match = _VERSION_RE.search(dockerfile_text)
    if match is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG FLUTTER_VERSION=<semver> pin"
        )
    return match.group("version")


def normalize_dart_sdk_version(raw: str) -> str:
    """Return the leading x.y.z token from a Flutter dart_sdk_version field."""
    match = _DART_VERSION_TOKEN_RE.search(raw.strip())
    if match is None:
        raise SystemExit(f"invalid dart_sdk_version: {raw!r}")
    return match.group(0)


def assert_dockerfile_uses_archive_path_arg(dockerfile_text: str) -> None:
    """Fail when the Flutter download URL hardcodes an archive path."""
    if _ARCHIVE_PATH_URL_RE.search(dockerfile_text) is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: Flutter download URL must use "
            "${FLUTTER_ARCHIVE_PATH} (not a hardcoded archive path)"
        )


def _validate_archive_path(archive_path: str) -> None:
    if not _ARCHIVE_PATH_RE.fullmatch(archive_path):
        raise SystemExit(f"invalid Flutter archive path: {archive_path!r}")


def replace_sdk_pin_args(
    dockerfile_text: str, pins: FlutterReleasePins
) -> str:
    """Return Dockerfile text with Flutter / Dart pin ARGs replaced."""
    if not _SHA256_RE.fullmatch(pins.flutter_sha256_amd64):
        raise SystemExit(
            f"invalid SHA-256 digest for flutter amd64: "
            f"{pins.flutter_sha256_amd64!r}"
        )
    if not _SHA256_RE.fullmatch(pins.dart_sha256_arm64):
        raise SystemExit(
            f"invalid SHA-256 digest for dart arm64: "
            f"{pins.dart_sha256_arm64!r}"
        )
    if not _DART_VERSION_RE.fullmatch(pins.dart_sdk_version):
        raise SystemExit(
            f"invalid dart_sdk_version: {pins.dart_sdk_version!r}"
        )
    _validate_archive_path(pins.archive_path)

    if _FLUTTER_SHA_ARG_RE.search(dockerfile_text) is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG FLUTTER_SHA256_AMD64 pin"
        )
    if _ARCHIVE_PATH_ARG_RE.search(dockerfile_text) is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG FLUTTER_ARCHIVE_PATH pin"
        )
    if _DART_VERSION_ARG_RE.search(dockerfile_text) is None:
        raise SystemExit(f"{DOCKERFILE_REL}: missing ARG DART_SDK_VERSION pin")
    if _DART_SHA_ARG_RE.search(dockerfile_text) is None:
        raise SystemExit(
            f"{DOCKERFILE_REL}: missing ARG DART_SHA256_ARM64 pin"
        )

    updated = _FLUTTER_SHA_ARG_RE.sub(
        rf"\g<1>{pins.flutter_sha256_amd64}",
        dockerfile_text,
        count=1,
    )
    updated = _ARCHIVE_PATH_ARG_RE.sub(
        rf"\g<1>{pins.archive_path}",
        updated,
        count=1,
    )
    updated = _DART_VERSION_ARG_RE.sub(
        rf"\g<1>{pins.dart_sdk_version}",
        updated,
        count=1,
    )
    return _DART_SHA_ARG_RE.sub(
        rf"\g<1>{pins.dart_sha256_arm64}",
        updated,
        count=1,
    )


def _pins_from_release_entry(
    entry: dict[str, Any], version: str
) -> FlutterReleasePins:
    """Validate one releases_linux.json entry and return pins."""
    sha256 = str(entry.get("sha256") or "")
    dart_raw = str(entry.get("dart_sdk_version") or "")
    archive = str(entry.get("archive") or "")
    if not _SHA256_RE.fullmatch(sha256):
        raise SystemExit(f"malformed Flutter sha256 for {version}: {sha256!r}")
    if not archive:
        raise SystemExit(f"missing Flutter archive path for {version}")
    _validate_archive_path(archive)
    dart_ver = normalize_dart_sdk_version(dart_raw)
    return FlutterReleasePins(
        flutter_sha256_amd64=sha256,
        dart_sdk_version=dart_ver,
        archive_path=archive,
    )


def fetch_flutter_linux_pins(
    version: str,
    *,
    opener: Callable[..., Any] | None = None,
    timeout: float = 30,
) -> FlutterReleasePins:
    """Fetch Flutter Linux stable archive path, SHA-256, and bundled Dart."""
    open_url = opener or urllib.request.urlopen
    with open_url(_FLUTTER_RELEASES_URL, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    releases = payload.get("releases")
    if not isinstance(releases, list):
        raise SystemExit(
            "malformed Flutter releases index: missing releases list"
        )
    matches: list[tuple[str, dict[str, Any]]] = []
    for entry in releases:
        if not isinstance(entry, dict):
            continue
        if entry.get("channel") != "stable":
            continue
        if entry.get("version") != version:
            continue
        matches.append((str(entry.get("release_date") or ""), entry))
    if not matches:
        raise SystemExit(
            f"Flutter stable Linux release not found for version {version}"
        )
    matches.sort(key=lambda item: item[0], reverse=True)
    return _pins_from_release_entry(matches[0][1], version)


def fetch_dart_arm64_sha256(
    version: str,
    *,
    opener: Callable[..., Any] | None = None,
    timeout: float = 30,
) -> str:
    """Fetch dartsdk-linux-arm64-release.zip SHA-256 for a Dart SDK version."""
    url = _DART_ARM64_SHA256_URL.format(version=version)
    open_url = opener or urllib.request.urlopen
    with open_url(url, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    digest = body.split()[0] if body.strip() else ""
    if not _SHA256_RE.fullmatch(digest):
        raise SystemExit(f"malformed checksum from {url}: {body!r}")
    return digest


def sync_dockerfile_pins(
    repo_root: Path,
    *,
    fetch_flutter: FetchFlutterFn | None = None,
    fetch_dart_arm64: FetchDartFn | None = None,
    check: bool = False,
) -> bool:
    """
    Align .cursor/Dockerfile Flutter / Dart pin ARGs with upstream digests.

    Returns True when the file would change (or differs in check mode).
    """
    path = repo_root / DOCKERFILE_REL
    if not path.is_file():
        raise SystemExit(f"Dockerfile not found: {path}")

    fetch_flutter_fn = fetch_flutter or fetch_flutter_linux_pins
    fetch_dart_fn = fetch_dart_arm64 or fetch_dart_arm64_sha256
    text = path.read_text(encoding="utf-8")
    assert_dockerfile_uses_archive_path_arg(text)
    version = parse_flutter_version(text)
    flutter_pins = fetch_flutter_fn(version)
    dart_arm64 = fetch_dart_fn(flutter_pins.dart_sdk_version)
    pins = FlutterReleasePins(
        flutter_sha256_amd64=flutter_pins.flutter_sha256_amd64,
        dart_sdk_version=flutter_pins.dart_sdk_version,
        dart_sha256_arm64=dart_arm64,
        archive_path=flutter_pins.archive_path,
    )
    updated = replace_sdk_pin_args(text, pins)

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
            "Refresh .cursor/Dockerfile Flutter / Dart SDK pin ARGs from "
            "flutter_infra_release and dart-archive for ARG FLUTTER_VERSION"
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when Dockerfile pin ARGs do not match upstream digests",
    )
    args = parser.parse_args()

    drift = sync_dockerfile_pins(get_repo_root(), check=args.check)
    if args.check and drift:
        print(
            f"Error: {DOCKERFILE_REL} Flutter / Dart pin ARGs are out of "
            "sync with upstream for ARG FLUTTER_VERSION. "
            "Run: PYTHONPATH=. python3 scripts/flutter_sdk_pins.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
