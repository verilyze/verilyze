#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build a simple SVG coverage badge from Cobertura root line-rate."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Same banding as common Shields.io coverage palettes (line fail-under is 85%
# in this repo; 70% is a softer floor).
_THRESHOLD_GREEN = 85.0
_THRESHOLD_YELLOW = 70.0

_COLOR_GREEN = "#4c1"
_COLOR_ORANGE = "#fe7d37"
_COLOR_RED = "#e05d44"


_LINE_RATE_RE = re.compile(
    r"<coverage\b[^>]*\bline-rate=\"([0-9]+(?:\.[0-9]+)?)\"",
    re.DOTALL,
)


def parse_line_rate_percent(cobertura_path: Path) -> float:
    """Return line coverage percent from root ``<coverage line-rate=.../>``."""
    text = cobertura_path.read_text(encoding="utf-8")
    m = _LINE_RATE_RE.search(text)
    if not m:
        msg = "could not find line-rate on root <coverage>"
        raise ValueError(msg)
    rate = float(m.group(1))
    return round(rate * 100.0, 2)


def badge_color_for_percent(percent: float) -> str:
    """Pick a Shields-style hex color from aggregate line percent."""
    if percent >= _THRESHOLD_GREEN:
        return _COLOR_GREEN
    if percent >= _THRESHOLD_YELLOW:
        return _COLOR_ORANGE
    return _COLOR_RED


def render_badge_svg(label: str, percent: float) -> str:
    """Two-part flat badge: gray label + colored percent."""
    color = badge_color_for_percent(percent)
    pct_text = f"{percent:.2f}%"
    # Approximate widths (px) for 11px DejaVu / sans text.
    lw = 7 * len(label) + 18
    rw = 7 * len(pct_text) + 16
    total = lw + rw
    aria = f"{label} coverage {pct_text}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" '
        f'height="20" role="img" aria-label="{aria}">\n'
        f"  <title>{aria}</title>\n"
        '  <linearGradient id="smooth" x2="0" y2="100%">\n'
        '    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>\n'
        '    <stop offset="1" stop-opacity=".1"/>\n'
        "  </linearGradient>\n"
        f'  <rect rx="3" width="{total}" height="20" fill="#555"/>\n'
        f'  <rect rx="3" x="{lw}" width="{rw}" height="20" '
        f'fill="{color}"/>\n'
        f'  <path fill="url(#smooth)" d="M0 0h{total}v20H0z"/>\n'
        '  <g fill="#fff" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" '
        'font-size="11" font-weight="bold">\n'
        f'    <text x="{lw // 2}" y="15" text-anchor="middle">{label}'
        "</text>\n"
        f'    <text x="{lw + rw // 2}" y="15" text-anchor="middle">'
        f"{pct_text}</text>\n"
        "  </g>\n"
        "</svg>\n"
    )


def write_badge_from_cobertura(
    cobertura_path: Path, label: str, output_path: Path
) -> None:
    """Read Cobertura XML and write an SVG badge to ``output_path``."""
    pct = parse_line_rate_percent(cobertura_path)
    svg = render_badge_svg(label, pct)
    output_path.write_text(svg, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """CLI entry; returns an exit code."""
    parser = argparse.ArgumentParser(
        description="Write an SVG badge from Cobertura line-rate."
    )
    parser.add_argument(
        "--label", required=True, help="Left segment, e.g. rust"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        type=Path,
        help="Cobertura XML path",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Output .svg path",
    )
    args = parser.parse_args(argv)
    try:
        write_badge_from_cobertura(args.input, args.label, args.output)
    except (OSError, ValueError) as e:
        print(f"cobertura_line_badge_svg: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
