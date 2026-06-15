# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for per-file Python coverage gate."""

from pathlib import Path

from scripts.coverage_per_file_check import check_per_file_coverage, main


def test_normalize_script_filename_handles_cobertura_forms() -> None:
    from scripts.coverage_per_file_check import _normalize_script_filename

    assert _normalize_script_filename("scripts/bar.py") == "scripts/bar.py"
    assert _normalize_script_filename("baz.py") == "scripts/baz.py"
    assert _normalize_script_filename("scripts/foo.txt") is None
    assert _normalize_script_filename("other/foo.py") is None


def test_production_script_classes_ignores_non_python_entries(
    tmp_path: Path,
) -> None:
    from scripts.coverage_per_file_check import production_script_classes
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        """<coverage><packages><package><classes>
          <class filename="scripts/foo.txt" line-rate="0.5"/>
          <class filename="other/foo.py" line-rate="0.5"/>
          <class filename="scripts/bar.py" line-rate="0.96"/>
          <class filename="baz.py" line-rate="0.97"/>
        </classes></package></packages></coverage>"""
    )
    rates = production_script_classes(root)
    assert rates == {
        "scripts/bar.py": 96.0,
        "scripts/baz.py": 97.0,
    }


def test_check_per_file_coverage_passes_when_all_modules_meet_threshold(
    tmp_path: Path,
) -> None:
    xml = tmp_path / "cobertura.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.98">
  <packages>
    <package>
      <classes>
        <class filename="scripts/foo.py" line-rate="0.96"/>
      </classes>
    </package>
  </packages>
</coverage>
""",
        encoding="utf-8",
    )
    assert check_per_file_coverage(xml, min_line_rate=95) == []


def test_check_per_file_coverage_fails_for_low_module(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.90">
  <packages>
    <package>
      <classes>
        <class filename="scripts/foo.py" line-rate="0.80"/>
      </classes>
    </package>
  </packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_per_file_coverage(xml, min_line_rate=95)
    assert len(errors) == 1
    assert "scripts/foo.py" in errors[0]


def test_check_per_file_coverage_reports_missing_xml(tmp_path: Path) -> None:
    missing = tmp_path / "missing.xml"
    errors = check_per_file_coverage(missing)
    assert len(errors) == 1
    assert "not found" in errors[0]


def test_check_per_file_coverage_reports_empty_script_classes(
    tmp_path: Path,
) -> None:
    xml = tmp_path / "cobertura.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="1.0">
  <packages><package><classes>
    <class filename="other/foo.py" line-rate="1.0"/>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    errors = check_per_file_coverage(xml)
    assert errors == ["no scripts/*.py classes found in coverage XML"]


def test_main_cli_returns_zero_on_success(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="1.0">
  <packages><package><classes>
    <class filename="scripts/foo.py" line-rate="1.0"/>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    assert main([str(xml)]) == 0


def test_main_cli_returns_nonzero_on_failure(tmp_path: Path) -> None:
    xml = tmp_path / "cobertura.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.50">
  <packages><package><classes>
    <class filename="scripts/foo.py" line-rate="0.50"/>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    assert main([str(xml)]) == 1
