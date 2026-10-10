# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/rust_version.py."""

from pathlib import Path

import pytest

from scripts.rust_version import (
    format_rust_version,
    parse_rust_version,
    read_msrv,
    read_toolchain_channel,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1.98", (1, 98)),
        ("1.98.1", (1, 98)),
        ("1.99.0", (1, 99)),
        ("  1.98.1  ", (1, 98)),
    ],
)
def test_parse_rust_version(text: str, expected: tuple[int, int]) -> None:
    assert parse_rust_version(text) == expected


@pytest.mark.parametrize("text", ["", "nightly", "stable", "1", "1.x", "x.1"])
def test_parse_rust_version_rejects_non_numeric(text: str) -> None:
    with pytest.raises(ValueError, match="Rust version"):
        parse_rust_version(text)


def test_format_rust_version() -> None:
    assert format_rust_version((1, 98)) == "1.98"


def test_versions_order_by_minor() -> None:
    assert parse_rust_version("1.98.1") < parse_rust_version("1.99")
    assert parse_rust_version("1.100") > parse_rust_version("1.99")


def test_read_msrv_reads_workspace_package(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[workspace.package]\nrust-version = "1.98"\n', encoding="utf-8"
    )
    assert read_msrv(tmp_path) == (1, 98)


def test_read_msrv_missing_field(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "[workspace.package]\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="rust-version"):
        read_msrv(tmp_path)


def test_read_toolchain_channel(tmp_path: Path) -> None:
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.99.0"\n', encoding="utf-8"
    )
    assert read_toolchain_channel(tmp_path) == "1.99.0"


def test_read_toolchain_channel_absent(tmp_path: Path) -> None:
    assert read_toolchain_channel(tmp_path) is None
    (tmp_path / "rust-toolchain.toml").write_text(
        "[toolchain]\ncomponents = ['rustfmt']\n", encoding="utf-8"
    )
    assert read_toolchain_channel(tmp_path) is None
