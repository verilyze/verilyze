# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hash-pinned REUSE lockfile and ensure-reuse.sh wiring for Scorecard."""

import re
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()


def test_requirements_reuse_txt_has_reuse_with_hashes() -> None:
    path = _ROOT / "scripts" / "requirements-reuse.txt"
    text = path.read_text(encoding="utf-8")
    assert re.search(r"^reuse==[0-9]+\.[0-9]+\.[0-9]+", text, re.MULTILINE), (
        "lockfile must list reuse== with a PEP 440 version"
    )
    assert "\n    --hash=sha256:" in text, "reuse dependencies must be hash-pinned"


def test_ensure_reuse_uses_require_hashes_and_lockfile() -> None:
    script = (_ROOT / "scripts" / "ensure-reuse.sh").read_text(encoding="utf-8")
    assert "scripts/requirements-reuse.txt" in script
    assert "--require-hashes" in script
    assert "pipx run --spec" in script
