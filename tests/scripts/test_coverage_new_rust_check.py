# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for per-new-file Rust coverage gate (ship-pr)."""

from pathlib import Path
from unittest.mock import patch

from scripts.coverage_new_rust_check import (
    NEW_RUST_MIN_FUNCTION_RATE,
    NEW_RUST_MIN_LINE_RATE,
    NEW_RUST_MIN_REGION_RATE,
    check_new_rust_coverage,
    discover_added_rust_files,
    main,
    normalize_rust_path,
    rust_file_rates,
)


def test_normalize_rust_path_matches_repo_relative_suffix() -> None:
    assert (
        normalize_rust_path("crates/vlz/src/foo.rs", "crates/vlz/src/foo.rs")
        == "crates/vlz/src/foo.rs"
    )
    assert (
        normalize_rust_path("vlz/crates/vlz/src/foo.rs", "crates/vlz/src/foo.rs")
        == "crates/vlz/src/foo.rs"
    )
    assert normalize_rust_path("foo.txt", "crates/vlz/src/foo.rs") is None


def test_rust_file_rates_maps_cobertura_classes() -> None:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        """<coverage><packages><package><classes>
          <class filename="crates/foo/src/a.rs" line-rate="0.96"
                 branch-rate="0.95">
            <methods>
              <method name="run" line-rate="0.91"/>
            </methods>
          </class>
          <class filename="crates/foo/src/b.rs" line-rate="0.50"
                 branch-rate="0.40"/>
        </classes></package></packages></coverage>"""
    )
    rates = rust_file_rates(root)
    assert rates["crates/foo/src/a.rs"]["line"] == 96.0
    assert rates["crates/foo/src/a.rs"]["region"] == 95.0
    assert rates["crates/foo/src/a.rs"]["function"] == 91.0
    assert rates["crates/foo/src/b.rs"]["line"] == 50.0


def test_rust_file_rates_skips_non_rust_filenames() -> None:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        """<coverage><packages><package><classes>
          <class filename="crates/foo/src/readme.txt" line-rate="0.10"/>
          <class filename="crates/foo/src/ok.rs" line-rate="0.99"
                 branch-rate="0.99"/>
        </classes></package></packages></coverage>"""
    )
    rates = rust_file_rates(root)
    assert list(rates) == ["crates/foo/src/ok.rs"]


def test_discover_added_rust_files_empty_base_returns_empty() -> None:
    assert discover_added_rust_files("") == []
    assert discover_added_rust_files("   ") == []


def test_discover_added_rust_files_parses_git_output() -> None:
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": "crates/vlz/src/new.rs\n\n", "stderr": ""},
    )()
    with patch(
        "scripts.coverage_new_rust_check.subprocess.run",
        return_value=completed,
    ):
        assert discover_added_rust_files("origin/main") == [
            "crates/vlz/src/new.rs"
        ]


def test_discover_added_rust_files_raises_on_git_failure() -> None:
    completed = type(
        "Completed",
        (),
        {"returncode": 128, "stdout": "", "stderr": "bad revision"},
    )()
    with patch(
        "scripts.coverage_new_rust_check.subprocess.run",
        return_value=completed,
    ):
        try:
            discover_added_rust_files("origin/main")
        except RuntimeError as exc:
            assert "bad revision" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")


def test_check_new_rust_coverage_reports_missing_xml(tmp_path: Path) -> None:
    missing = tmp_path / "missing.xml"
    errors = check_new_rust_coverage(missing, ["crates/vlz/src/new.rs"])
    assert len(errors) == 1
    assert "not found" in errors[0]


def test_check_new_rust_coverage_reports_empty_rust_classes(
    tmp_path: Path,
) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="1.0">
  <packages><package><classes>
    <class filename="readme.txt" line-rate="1.0"/>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_new_rust_coverage(xml, ["crates/vlz/src/new.rs"])
    assert errors == ["no Rust .rs classes found in coverage XML"]


def test_check_new_rust_coverage_fails_low_function(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.99">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.99"
           branch-rate="0.99">
      <methods><method name="f" line-rate="0.50"/></methods>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_new_rust_coverage(
        xml,
        ["crates/vlz/src/new.rs"],
        min_line_rate=95,
        min_function_rate=90,
        min_region_rate=95,
    )
    assert len(errors) == 1
    assert "function coverage" in errors[0]


def test_check_new_rust_coverage_fails_low_region(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.99">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.99"
           branch-rate="0.50">
      <methods><method name="f" line-rate="0.99"/></methods>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_new_rust_coverage(
        xml,
        ["crates/vlz/src/new.rs"],
        min_line_rate=95,
        min_function_rate=90,
        min_region_rate=95,
    )
    assert len(errors) == 1
    assert "region coverage" in errors[0]


def test_check_new_rust_coverage_passes_at_thresholds(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.99">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.95"
           branch-rate="0.95">
      <methods><method name="f" line-rate="0.90"/></methods>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_new_rust_coverage(
        xml,
        ["crates/vlz/src/new.rs"],
        min_line_rate=NEW_RUST_MIN_LINE_RATE,
        min_function_rate=NEW_RUST_MIN_FUNCTION_RATE,
        min_region_rate=NEW_RUST_MIN_REGION_RATE,
    )
    assert errors == []


def test_check_new_rust_coverage_fails_low_line(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.50">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.80"
           branch-rate="0.95">
      <methods><method name="f" line-rate="0.95"/></methods>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_new_rust_coverage(
        xml,
        ["crates/vlz/src/new.rs"],
        min_line_rate=95,
        min_function_rate=90,
        min_region_rate=95,
    )
    assert len(errors) == 1
    assert "line coverage" in errors[0]
    assert "crates/vlz/src/new.rs" in errors[0]


def test_check_new_rust_coverage_fails_missing_file_in_xml(
    tmp_path: Path,
) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="1.0">
  <packages><package><classes>
    <class filename="crates/vlz/src/other.rs" line-rate="1.0"
           branch-rate="1.0"/>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_new_rust_coverage(
        xml,
        ["crates/vlz/src/new.rs"],
        min_line_rate=95,
        min_function_rate=90,
        min_region_rate=95,
    )
    assert len(errors) == 1
    assert "not found in coverage XML" in errors[0]


def test_check_new_rust_coverage_skips_when_no_files() -> None:
    xml = Path("/nonexistent/cobertura-rust.xml")
    assert check_new_rust_coverage(xml, []) == []


def test_main_cli_returns_zero_when_no_new_files(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="1.0">
  <packages><package><classes/></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    assert main([str(xml)]) == 0


def test_main_cli_returns_nonzero_on_failure(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.50">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.50"
           branch-rate="0.50"/>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    assert (
        main(
            [
                str(xml),
                "--file",
                "crates/vlz/src/new.rs",
            ]
        )
        == 1
    )


def test_main_cli_git_base_failure_returns_nonzero(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="1.0">
  <packages><package><classes/></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    with patch(
        "scripts.coverage_new_rust_check.discover_added_rust_files",
        side_effect=RuntimeError("git diff failed"),
    ):
        assert main([str(xml), "--git-base", "origin/main"]) == 1


def test_main_cli_git_base_success_merges_files(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.99">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.96"
           branch-rate="0.96">
      <methods><method name="f" line-rate="0.95"/></methods>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    with patch(
        "scripts.coverage_new_rust_check.discover_added_rust_files",
        return_value=["crates/vlz/src/new.rs"],
    ):
        assert main([str(xml), "--git-base", "origin/main"]) == 0


def test_main_cli_normalizes_windows_paths(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura-rust.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.99">
  <packages><package><classes>
    <class filename="crates/vlz/src/new.rs" line-rate="0.96"
           branch-rate="0.96">
      <methods><method name="f" line-rate="0.95"/></methods>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    assert (
        main(
            [
                str(xml),
                "--file",
                ".\\crates\\vlz\\src\\new.rs",
            ]
        )
        == 0
    )
