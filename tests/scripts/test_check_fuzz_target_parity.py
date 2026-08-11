# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Tests for AFL vs cargo-fuzz target basename parity (ClusterFuzzLite)."""

from pathlib import Path

import pytest

from scripts.check_fuzz_target_parity import (
    afl_bin_names,
    cargo_fuzz_target_names,
    main,
    parity_errors,
)


def test_afl_bin_names_reads_bin_name_keys(tmp_path: Path) -> None:
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text(
        '[package]\nname = "vlz-fuzz"\n\n'
        '[[bin]]\nname = "fuzz_config_toml"\n'
        'path = "fuzz_targets/config_toml.rs"\n\n'
        '[[bin]]\nname = "fuzz_go_mod"\n'
        'path = "fuzz_targets/go_mod.rs"\n',
        encoding="utf-8",
    )
    assert afl_bin_names(cargo) == {"fuzz_config_toml", "fuzz_go_mod"}


def test_cargo_fuzz_target_names_from_rs_basenames(tmp_path: Path) -> None:
    targets = tmp_path / "fuzz_targets"
    targets.mkdir()
    (targets / "fuzz_config_toml.rs").write_text("//\n", encoding="utf-8")
    (targets / "fuzz_go_mod.rs").write_text("//\n", encoding="utf-8")
    (targets / "notes.txt").write_text("ignore\n", encoding="utf-8")
    assert cargo_fuzz_target_names(targets) == {
        "fuzz_config_toml",
        "fuzz_go_mod",
    }


def test_cargo_fuzz_target_names_missing_dir(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing cargo-fuzz targets dir"):
        cargo_fuzz_target_names(tmp_path / "nope")


def test_cargo_fuzz_target_names_empty_dir(tmp_path: Path) -> None:
    targets = tmp_path / "fuzz_targets"
    targets.mkdir()
    with pytest.raises(ValueError, match="no \\*\\.rs fuzz targets"):
        cargo_fuzz_target_names(targets)


def test_parity_errors_empty_when_sets_match() -> None:
    names = {"fuzz_a", "fuzz_b"}
    assert parity_errors(names, names) == []


def test_parity_errors_reports_missing_on_each_side() -> None:
    afl = {"fuzz_a", "fuzz_b"}
    cfl = {"fuzz_a", "fuzz_c"}
    errs = parity_errors(afl, cfl)
    assert any("fuzz_b" in e and "cargo-fuzz" in e for e in errs)
    assert any("fuzz_c" in e and "AFL" in e for e in errs)


def test_afl_bin_names_rejects_empty(tmp_path: Path) -> None:
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text('[package]\nname = "vlz-fuzz"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="no \\[\\[bin\\]\\]"):
        afl_bin_names(cargo)


def _seed_repo(root: Path) -> None:
    afl_dir = root / "tests" / "fuzz"
    afl_dir.mkdir(parents=True)
    (afl_dir / "Cargo.toml").write_text(
        '[[bin]]\nname = "fuzz_config_toml"\npath = "x.rs"\n',
        encoding="utf-8",
    )
    cfl = root / "fuzz" / "fuzz_targets"
    cfl.mkdir(parents=True)
    (cfl / "fuzz_config_toml.rs").write_text("//\n", encoding="utf-8")


def test_main_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _seed_repo(tmp_path)
    assert main(["--root", str(tmp_path)]) == 0
    assert "OK:" in capsys.readouterr().out


def test_main_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_repo(tmp_path)
    (tmp_path / "fuzz" / "fuzz_targets" / "fuzz_extra.rs").write_text(
        "//\n",
        encoding="utf-8",
    )
    assert main(["--root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "out of sync" in err
    assert "fuzz_extra" in err


def test_main_missing_afl_cargo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (tmp_path / "fuzz" / "fuzz_targets" / "fuzz_a.rs").write_text(
        "//\n",
        encoding="utf-8",
    )
    assert main(["--root", str(tmp_path)]) == 1
    assert "ERROR:" in capsys.readouterr().err
