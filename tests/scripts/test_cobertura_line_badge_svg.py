# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/cobertura_line_badge_svg.py."""

import importlib.util
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest

_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "scripts"
    / "cobertura_line_badge_svg.py"
)
_spec = importlib.util.spec_from_file_location(
    "cobertura_line_badge_svg", _script_path
)
cobertura_line_badge_svg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cobertura_line_badge_svg)  # type: ignore[union-attr]


MIN_COBERTURA = """<?xml version="1.0" ?>
<coverage line-rate="0.8533" branch-rate="0" version="1.9" timestamp="" lines-covered="1" lines-valid="1">
  <packages/>
</coverage>
"""


class TestParseLineRatePercent:
    def test_reads_root_line_rate(self, tmp_path: Path) -> None:
        p = tmp_path / "c.xml"
        p.write_text(MIN_COBERTURA, encoding="utf-8")
        assert cobertura_line_badge_svg.parse_line_rate_percent(p) == 85.33

    def test_full_line_rate(self, tmp_path: Path) -> None:
        p = tmp_path / "c.xml"
        p.write_text(
            MIN_COBERTURA.replace("0.8533", "1"),
            encoding="utf-8",
        )
        assert cobertura_line_badge_svg.parse_line_rate_percent(p) == 100.0

    def test_raises_when_line_rate_missing(self, tmp_path: Path) -> None:
        p = tmp_path / "c.xml"
        p.write_text("<coverage version=\"1.9\"><packages/></coverage>", encoding="utf-8")
        with pytest.raises(ValueError, match="could not find line-rate"):
            cobertura_line_badge_svg.parse_line_rate_percent(p)


class TestBadgeColor:
    def test_high_is_green(self) -> None:
        assert cobertura_line_badge_svg.badge_color_for_percent(90.0).upper() == "#4C1"

    def test_mid_is_orange(self) -> None:
        assert cobertura_line_badge_svg.badge_color_for_percent(
            75.0
        ).upper() == "#FE7D37"

    def test_low_is_red(self) -> None:
        assert cobertura_line_badge_svg.badge_color_for_percent(
            50.0
        ).upper() == "#E05D44"

    def test_threshold_green_boundary(self) -> None:
        assert cobertura_line_badge_svg.badge_color_for_percent(
            85.0
        ).upper() == "#4C1"

    def test_threshold_yellow_boundary(self) -> None:
        assert cobertura_line_badge_svg.badge_color_for_percent(
            70.0
        ).upper() == "#FE7D37"


class TestRenderBadgeSvg:
    def test_contains_label_and_percent(self) -> None:
        svg = cobertura_line_badge_svg.render_badge_svg("rust cov", 85.33)
        assert "rust cov" in svg
        assert "85.33" in svg or "85.3" in svg
        assert "xmlns=" in svg

    def test_accessibility_title(self) -> None:
        svg = cobertura_line_badge_svg.render_badge_svg("python cov", 100.0)
        assert "python cov" in svg.lower()
        assert "coverage" in svg.lower()


class TestWriteBadgeFromCobertura:
    def test_writes_svg_file(self, tmp_path: Path) -> None:
        c = tmp_path / "cobertura.xml"
        c.write_text(MIN_COBERTURA, encoding="utf-8")
        out = tmp_path / "out.svg"
        cobertura_line_badge_svg.write_badge_from_cobertura(
            c, "rust cov", out
        )
        text = out.read_text(encoding="utf-8")
        assert "<svg" in text
        assert "85.33" in text


class TestMain:
    def test_success_writes_svg(self, tmp_path: Path) -> None:
        c = tmp_path / "cobertura.xml"
        c.write_text(MIN_COBERTURA, encoding="utf-8")
        out = tmp_path / "out.svg"
        argv = ["--label", "rust cov", "-i", str(c), "-o", str(out)]
        assert cobertura_line_badge_svg.main(argv) == 0
        assert out.read_text(encoding="utf-8").startswith("<svg")

    def test_value_error_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        c = tmp_path / "bad.xml"
        c.write_text("<coverage version=\"1.9\"/>", encoding="utf-8")
        out = tmp_path / "out.svg"
        argv = ["--label", "rust cov", "-i", str(c), "-o", str(out)]
        assert cobertura_line_badge_svg.main(argv) == 1
        captured = capsys.readouterr()
        assert "cobertura_line_badge_svg:" in captured.err

    def test_oserror_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = tmp_path / "missing.xml"
        out = tmp_path / "out.svg"
        argv = ["--label", "rust cov", "-i", str(missing), "-o", str(out)]
        assert cobertura_line_badge_svg.main(argv) == 1
        captured = capsys.readouterr()
        assert "cobertura_line_badge_svg:" in captured.err


class TestMainModule:
    def test_main_module_exit_code(self, tmp_path: Path) -> None:
        c = tmp_path / "cobertura.xml"
        c.write_text(MIN_COBERTURA, encoding="utf-8")
        out = tmp_path / "out.svg"
        argv = [
            "cobertura_line_badge_svg.py",
            "--label",
            "rust cov",
            "-i",
            str(c),
            "-o",
            str(out),
        ]
        with patch("sys.argv", argv):
            try:
                runpy.run_path(str(_script_path), run_name="__main__")
            except SystemExit as exc:
                assert exc.code == 0
                return
        pytest.fail("Expected SystemExit from sys.exit(main())")
