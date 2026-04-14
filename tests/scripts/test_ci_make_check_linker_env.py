# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: CI check step sets explicit gcc+ld defaults."""

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_ci_make_check_step_sets_gcc_ld_env_defaults() -> None:
    text = (_repo_root() / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert "name: Run make -j check (full Makefile gate)" in text
    assert "CC: gcc" in text
    assert "RUSTFLAGS: -Clink-arg=-fuse-ld=bfd" in text
    assert "CXX: g++" not in text

