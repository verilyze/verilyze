#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Native gitleaks directory scan for check-super-linter-native.

Matches super-linter's gitleaks invocation shape (directory + redact + config)
so check-fast scans the working tree, including uncommitted files.

Build and cache trees listed in `.gitleaks.toml` allowlists are skipped as
scan roots so parallel `cargo` builds under `target/` cannot race gitleaks
`lstat` (partial-scan exit 1 with no leaks). Remaining transient partial
scans are retried a few times.
"""

import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

GITLEAKS_CONFIG_NAME = ".gitleaks.toml"
GITLEAKS_BIN = "gitleaks"

# Directory names skipped as scan roots (align with .gitleaks.toml allowlist
# and super-linter FILTER_REGEX_EXCLUDE intent).
GITLEAKS_SKIP_DIR_NAMES = frozenset(
    {
        "target",
        "__pycache__",
        ".mypy_cache",
        ".vlz",
        "super-linter-output",
    }
)

# Install hints for setup-system-deps parity (host package, not pip).
GITLEAKS_INSTALL_HINTS = (
    "Install hint (Debian/Ubuntu): see "
    "https://github.com/gitleaks/gitleaks#installing",
    "Install hint (Fedora): sudo dnf install gitleaks",
    "Install hint (openSUSE): sudo zypper install gitleaks",
)

_MISSING_ERROR = (
    "ERROR: gitleaks is required for check-fast / "
    "check-super-linter-native."
)

# Retries when cargo (parallel check-fast) removes files mid-walk.
GITLEAKS_PARTIAL_SCAN_RETRIES = 3


def missing_gitleaks_message() -> str:
    """Error text when the gitleaks binary is not on PATH."""
    lines = [_MISSING_ERROR, *GITLEAKS_INSTALL_HINTS]
    return "\n".join(lines) + "\n"


def report_missing_gitleaks() -> int:
    """Print missing-binary message to stderr; return non-zero."""
    sys.stderr.write(missing_gitleaks_message())
    return 1


def _should_skip_dir(name: str) -> bool:
    if name in GITLEAKS_SKIP_DIR_NAMES:
        return True
    if name.startswith(".venv"):
        return True
    return False


def iter_gitleaks_scan_paths(scan_root: Path) -> list[Path]:
    """Return child paths under `scan_root` to scan (skips build/cache dirs)."""
    if not scan_root.is_dir():
        return [scan_root]
    paths: list[Path] = []
    for child in sorted(scan_root.iterdir(), key=lambda p: p.name):
        if child.is_dir() and _should_skip_dir(child.name):
            continue
        paths.append(child)
    return paths


def build_gitleaks_directory_cmd(
    scan_root: Path, config_path: Path
) -> list[str]:
    """Return argv for a single-path worktree scan (super-linter shape)."""
    return [
        GITLEAKS_BIN,
        "directory",
        "--no-banner",
        "--redact",
        "--verbose",
        "--config",
        str(config_path),
        str(scan_root),
    ]


def is_transient_partial_scan(exit_code: int, output: str) -> bool:
    """True for non-zero exit from a no-leak gitleaks partial scan."""
    if exit_code == 0:
        return False
    lowered = output.lower()
    return "partial scan" in lowered and "no leaks found" in lowered


def run_gitleaks_directory(
    scan_root: Path, config_path: Path
) -> tuple[int, str]:
    """Run gitleaks over non-build paths; retry transient partial scans.

    Returns ``(exit_code, combined output)``.
    """
    if shutil.which(GITLEAKS_BIN) is None:
        return 1, missing_gitleaks_message()

    paths = iter_gitleaks_scan_paths(scan_root)
    if not paths:
        return 0, ""

    combined: list[str] = []
    worst_code = 0
    for path in paths:
        cmd = build_gitleaks_directory_cmd(path, config_path)
        code = 1
        output = ""
        for _attempt in range(GITLEAKS_PARTIAL_SCAN_RETRIES):
            completed = subprocess.run(  # nosec B603
                cmd,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            code = completed.returncode
            if code == 0 or not is_transient_partial_scan(code, output):
                break
        if output:
            combined.append(output)
        if code != 0:
            worst_code = code
    return worst_code, "".join(combined)


def main(argv: list[str] | None = None) -> int:
    """CLI: scan repo root (arg or default repo root)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) > 1:
        print(
            "Usage: gitleaks_native.py [SCAN_ROOT]",
            file=sys.stderr,
        )
        return 2
    if args:
        scan_root = Path(args[0]).resolve()
    else:
        scan_root = Path(__file__).resolve().parents[1]
    config_path = scan_root / GITLEAKS_CONFIG_NAME
    if not config_path.is_file():
        print(f"ERROR: missing {config_path}", file=sys.stderr)
        return 1
    code, output = run_gitleaks_directory(scan_root, config_path)
    if output:
        sys.stderr.write(output)
        if not output.endswith("\n"):
            sys.stderr.write("\n")
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
