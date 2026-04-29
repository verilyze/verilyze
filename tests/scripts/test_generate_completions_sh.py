# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Regression tests for scripts/generate_completions.sh race safety."""

from pathlib import Path


_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPT = _ROOT / "scripts" / "generate_completions.sh"


def test_generate_completions_uses_atomic_temp_writes() -> None:
    """Completions must be written via temp files then moved in place."""
    text = _SCRIPT.read_text(encoding="utf-8")
    assert "mktemp" in text
    assert "mv -f" in text


def test_generate_completions_enables_strict_shell_mode() -> None:
    """Script should fail fast to avoid writing partial outputs."""
    text = _SCRIPT.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
