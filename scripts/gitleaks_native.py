#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Native gitleaks directory scan for check-super-linter-native.

Matches super-linter's gitleaks invocation shape (directory + redact + config)
so check-fast scans the working tree, including uncommitted files.
"""

import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

GITLEAKS_CONFIG_NAME = ".gitleaks.toml"
GITLEAKS_BIN = "gitleaks"

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


def missing_gitleaks_message() -> str:
    """Error text when the gitleaks binary is not on PATH."""
    lines = [_MISSING_ERROR, *GITLEAKS_INSTALL_HINTS]
    return "\n".join(lines) + "\n"


def report_missing_gitleaks() -> int:
    """Print missing-binary message to stderr; return non-zero."""
    sys.stderr.write(missing_gitleaks_message())
    return 1


def build_gitleaks_directory_cmd(
    scan_root: Path, config_path: Path
) -> list[str]:
    """Return argv for a worktree scan (super-linter Gitleaks parity)."""
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


def run_gitleaks_directory(
    scan_root: Path, config_path: Path
) -> tuple[int, str]:
    """Run gitleaks directory; return (exit_code, combined output)."""
    if shutil.which(GITLEAKS_BIN) is None:
        return 1, missing_gitleaks_message()

    cmd = build_gitleaks_directory_cmd(scan_root, config_path)
    completed = subprocess.run(  # nosec B603
        cmd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output


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
