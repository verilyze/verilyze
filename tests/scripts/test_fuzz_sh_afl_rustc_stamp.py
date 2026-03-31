# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: fuzz.sh keeps cargo-afl LLVM runtime in sync with the active rustc (NFR-020)."""

from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _fuzz_sh_text() -> str:
    return (_repo_root() / "scripts" / "fuzz.sh").read_text(encoding="utf-8")


def test_fuzz_sh_defines_dry_afl_rs_data_dir() -> None:
    """AFLplusplus and the rustc stamp must share one XDG afl.rs base path."""
    text = _fuzz_sh_text()
    assert "_afl_rs_data=" in text, (
        "fuzz.sh must set _afl_rs_data for DRY path to ~/.local/share/afl.rs (or XDG)"
    )
    assert "${_afl_rs_data}/AFLplusplus" in text or '"$_afl_rs_data/AFLplusplus"' in text, (
        "AFLplusplus clone path must be under _afl_rs_data"
    )


def test_fuzz_sh_uses_rustc_stamp_file_under_afl_rs() -> None:
    text = _fuzz_sh_text()
    assert "rustc-stamp-for-afl" in text
    assert "${_afl_rs_data}/rustc-stamp-for-afl" in text or (
        '"$_afl_rs_data/rustc-stamp-for-afl"' in text
    ), "Stamp path must live next to AFLplusplus under _afl_rs_data"


def test_fuzz_sh_compares_rustc_identity_for_stamp() -> None:
    text = _fuzz_sh_text()
    assert "rustc -vV" in text, "fuzz.sh must capture rustc identity (rustc -vV) for the stamp"


def test_fuzz_sh_rebuilds_afl_when_stamp_mismatches() -> None:
    text = _fuzz_sh_text()
    assert "cargo afl config --build" in text
    assert "--force" in text, (
        "fuzz.sh must fall back to cargo afl config --build --force when plain --build fails"
    )

