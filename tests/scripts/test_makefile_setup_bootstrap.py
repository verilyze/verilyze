# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: setup bootstraps first-run contributor tooling."""

from pathlib import Path

from tests.scripts.test_makefile_check_includes_deny import _extract_prerequisite_block


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_setup_depends_on_setup_dev_tools() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "setup")
    tokens = block.replace("\\", " ").split()
    assert "setup-dev-tools" in tokens, (
        "make setup should bootstrap non-system developer tools before "
        "running checks"
    )


def test_setup_dev_tools_target_installs_rust_cli_tools() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "setup-dev-tools")
    tokens = block.replace("\\", " ").split()
    assert "setup-cargo-deny" in tokens
    assert "setup-cargo-about" in tokens
    assert "setup-cargo-llvm-cov" in tokens

