# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Verify OBS release source uploads."""

import argparse
import hashlib
import re
import subprocess  # nosec B404
import sys
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path

VENDOR_LOCKFILE_PATH = "Cargo.lock"
_SHA256_ATTR_PATTERN = re.compile(
    r'<file\s+[^>]*name="([^"]+)"[^>]*sha256="([0-9a-fA-F]{64})"',
    re.MULTILINE,
)


def sha256_bytes(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest for ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return lowercase hex SHA-256 digest for ``path``."""
    return sha256_bytes(path.read_bytes())


def extract_cargo_lock_from_vendor_archive(vendor_archive: Path) -> bytes:
    """Extract ``Cargo.lock`` bytes from a ``vendor.tar.zst`` archive."""
    proc = subprocess.run(  # nosec B603 B607
        ["tar", "--zstd", "-xOf", str(vendor_archive), VENDOR_LOCKFILE_PATH],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = f"{vendor_archive}: missing {VENDOR_LOCKFILE_PATH}"
        raise ValueError(msg)
    return proc.stdout


def git_show_cargo_lock(repo_root: Path, git_ref: str) -> bytes:
    """Return ``Cargo.lock`` bytes from ``git show git_ref:Cargo.lock``."""
    proc = subprocess.run(  # nosec B603 B607
        ["git", "-C", str(repo_root), "show", f"{git_ref}:Cargo.lock"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        msg = f"unable to read Cargo.lock at {git_ref}: {stderr}"
        raise ValueError(msg)
    return proc.stdout


def verify_vendor_lockfile_matches_git_ref(
    *,
    repo_root: Path,
    git_ref: str,
    vendor_archive: Path,
) -> None:
    """Fail when vendored ``Cargo.lock`` differs from the release git tree."""
    expected = git_show_cargo_lock(repo_root, git_ref)
    actual = extract_cargo_lock_from_vendor_archive(vendor_archive)
    if actual != expected:
        msg = (
            f"{vendor_archive}: Cargo.lock does not match "
            f"{git_ref}:Cargo.lock in {repo_root}"
        )
        raise ValueError(msg)


def parse_obs_file_checksums(meta_or_files: Path) -> dict[str, str]:
    """Parse OBS ``.osc/_files`` or ``_meta`` XML for per-file sha256 sums."""
    text = meta_or_files.read_text(encoding="utf-8")
    checksums = {
        name: digest.lower()
        for name, digest in _SHA256_ATTR_PATTERN.findall(text)
    }
    if checksums:
        return checksums

    root = ET.fromstring(text)  # nosec B314
    for file_elem in root.iter("file"):
        name = file_elem.get("name")
        if not name:
            continue
        for child in file_elem:
            if child.tag == "checksum" and child.get("type") == "sha256":
                value = (child.text or "").strip().lower()
                if value:
                    checksums[name] = value
    return checksums


def _obs_checksum_sources(package_dir: Path) -> list[Path]:
    candidates = [
        package_dir / ".osc" / "_files",
        package_dir / "_meta",
    ]
    return [path for path in candidates if path.is_file()]


def verify_obs_upload_checksums(
    *,
    package_dir: Path,
    expected: dict[str, str],
) -> None:
    """Verify OBS checkout files and metadata match expected digests."""
    normalized = {name: digest.lower() for name, digest in expected.items()}
    for filename, expected_digest in normalized.items():
        file_path = package_dir / filename
        if not file_path.is_file():
            msg = f"{package_dir}: missing uploaded file {filename}"
            raise ValueError(msg)
        actual_digest = sha256_file(file_path)
        if actual_digest != expected_digest:
            msg = (
                f"{file_path}: checksum mismatch "
                f"(expected {expected_digest}, got {actual_digest})"
            )
            raise ValueError(msg)

    meta_checksums: dict[str, str] = {}
    for source in _obs_checksum_sources(package_dir):
        meta_checksums.update(parse_obs_file_checksums(source))

    if not meta_checksums:
        return

    for filename, expected_digest in normalized.items():
        meta_digest = meta_checksums.get(filename)
        if meta_digest is None:
            msg = f"{package_dir}: OBS metadata missing {filename}"
            raise ValueError(msg)
        if meta_digest != expected_digest:
            msg = (
                f"{package_dir}: OBS metadata checksum mismatch "
                f"for {filename} (expected {expected_digest}, "
                f"metadata has {meta_digest})"
            )
            raise ValueError(msg)


def _cmd_vendor_lockfile(args: argparse.Namespace) -> int:
    verify_vendor_lockfile_matches_git_ref(
        repo_root=Path(args.repo_root),
        git_ref=args.git_ref,
        vendor_archive=Path(args.vendor_archive),
    )
    return 0


def _cmd_package_checksums(args: argparse.Namespace) -> int:
    expected: dict[str, str] = {}
    for item in args.expected:
        name, digest = item.split("=", 1)
        expected[name] = digest
    verify_obs_upload_checksums(
        package_dir=Path(args.package_dir),
        expected=expected,
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify OBS release source uploads.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    vendor_cmd = subparsers.add_parser(
        "vendor-lockfile",
        help="Verify vendor archive Cargo.lock matches a git ref",
    )
    vendor_cmd.add_argument("--repo-root", required=True)
    vendor_cmd.add_argument("--git-ref", required=True)
    vendor_cmd.add_argument("--vendor-archive", required=True)
    vendor_cmd.set_defaults(command="vendor-lockfile")

    checksum_cmd = subparsers.add_parser(
        "package-checksums",
        help="Verify OBS package checkout checksums",
    )
    checksum_cmd.add_argument("--package-dir", required=True)
    checksum_cmd.add_argument(
        "--expected",
        action="append",
        required=True,
        metavar="FILE=SHA256",
        help="Expected sha256 digest for an uploaded file",
    )
    checksum_cmd.set_defaults(command="package-checksums")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "vendor-lockfile":
            return _cmd_vendor_lockfile(args)
        return _cmd_package_checksums(args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
