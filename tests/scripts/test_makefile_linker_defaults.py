# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: Makefile provides override-friendly gcc+ld defaults."""

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_makefile_has_gcc_ld_default_variables() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "CC ?= gcc" in text
    assert "VLZ_LINKER_RUSTFLAG ?= -Clink-arg=-fuse-ld=bfd" in text
    assert "RUSTFLAGS ?= $(VLZ_LINKER_RUSTFLAG)" in text


def test_makefile_clippy_preserves_linker_rustflags() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert (
        'cd "$(MKFILE_DIR)" && RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" cargo clippy '
        "--all-targets --all-features"
    ) in text


def test_setup_system_deps_checks_gcc_and_ld_bfd_not_gpp() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "command -v gcc" in text
    assert "command -v ld.bfd" in text
    assert "command -v g++" not in text

