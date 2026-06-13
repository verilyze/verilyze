# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS .changes rendering from CHANGELOG.md."""

from __future__ import annotations

import os
import runpy
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import render_obs_changes

_ROOT = Path(__file__).resolve().parent.parent.parent
_RENDER_SCRIPT = _ROOT / "scripts" / "render_obs_changes.py"
_ENV_FILE = _ROOT / "packaging" / "obs" / "obs-project.env"

_SAMPLE_CHANGELOG = """\
# Changelog

## [1.2.3] - 2026-06-07

### Fixed

- First fixed item.
- Second fixed item with details.

### Changed

- One changed item.

## [1.2.2] - 2026-05-01

### Added

- Older release item.
"""

_EXISTING_CHANGES = """\
-------------------------------------------------------------------
Mon May  1 10:00:00 UTC 2026 - Travis Post <post.travis@gmail.com> - 1.2.2

- Older release item.
"""

_FIXED_TIMESTAMP = datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc)


def test_converts_changelog_section_into_obs_entry() -> None:
    bullets = render_obs_changes.changelog_section_to_bullets(
        render_obs_changes.extract_changelog_section(_SAMPLE_CHANGELOG, "1.2.3")
    )
    entry = render_obs_changes.format_obs_entry(
        "1.2.3",
        bullets,
        "Travis Post <post.travis@gmail.com>",
        now=_FIXED_TIMESTAMP,
    )
    assert entry.startswith(
        "-------------------------------------------------------------------\n"
        "Sun Jun  7 12:00:00 UTC 2026 - Travis Post <post.travis@gmail.com> - 1.2.3\n"
    )
    assert "- Fixed: First fixed item." in entry
    assert "- Fixed: Second fixed item with details." in entry
    assert "- Changed: One changed item." in entry


def test_render_changes_prepends_to_existing_file(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")
    existing = tmp_path / "verilyze.changes"
    existing.write_text(_EXISTING_CHANGES, encoding="utf-8")

    output = render_obs_changes.render_changes(
        "1.2.3",
        changelog,
        render_obs_changes.RenderChangesContext(
            existing_changes_path=existing,
            maintainer="Travis Post <post.travis@gmail.com>",
            now=_FIXED_TIMESTAMP,
        ),
    )

    assert output.index(" - 1.2.3\n") < output.index(" - 1.2.2\n")
    assert "- Fixed: First fixed item." in output
    assert "- Older release item." in output


def test_render_changes_skips_prepend_when_version_already_at_top(
    tmp_path: Path,
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")
    existing = tmp_path / "verilyze.changes"
    existing.write_text(
        render_obs_changes.format_obs_entry(
            "1.2.3",
            ["- Fixed: First fixed item."],
            "Travis Post <post.travis@gmail.com>",
            now=_FIXED_TIMESTAMP,
        ),
        encoding="utf-8",
    )

    output = render_obs_changes.render_changes(
        "1.2.3",
        changelog,
        render_obs_changes.RenderChangesContext(
            existing_changes_path=existing,
            maintainer="Travis Post <post.travis@gmail.com>",
            now=_FIXED_TIMESTAMP,
        ),
    )

    assert output == existing.read_text(encoding="utf-8")


def test_render_changes_fails_when_version_section_missing(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")

    with pytest.raises(render_obs_changes.ChangelogSectionNotFoundError):
        render_obs_changes.render_changes(
            "9.9.9",
            changelog,
            render_obs_changes.RenderChangesContext(
                maintainer="Travis Post <post.travis@gmail.com>",
                now=_FIXED_TIMESTAMP,
            ),
        )


def test_render_changes_uses_maintainer_from_obs_project_env(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")

    output = render_obs_changes.render_changes(
        "1.2.3",
        changelog,
        render_obs_changes.RenderChangesContext(
            config_path=_ENV_FILE,
            now=_FIXED_TIMESTAMP,
        ),
    )

    env = render_obs_changes.load_obs_project_env(_ENV_FILE)
    assert env.obs_maintainer in output


def test_render_changes_truncates_long_bullet_lists() -> None:
    section = "\n".join(
        [
            "## [1.0.0]",
            "",
            "### Added",
            "",
        ]
        + [f"- Item {index}." for index in range(1, 30)]
    )
    bullets = render_obs_changes.changelog_section_to_bullets(section)
    assert len(bullets) <= render_obs_changes.MAX_BULLETS
    assert bullets[-1] == render_obs_changes.TRUNCATION_NOTE


def test_validate_release_version_rejects_invalid_semver() -> None:
    with pytest.raises(SystemExit) as exc_info:
        render_obs_changes.validate_release_version("v1.2.3")
    assert exc_info.value.code == 2


def test_changelog_section_to_bullets_skips_empty_bullet_text() -> None:
    bullets = render_obs_changes.changelog_section_to_bullets("-    \n- Real item.")
    assert bullets == ["- Real item."]


def test_changelog_section_to_bullets_handles_uncategorized_items() -> None:
    bullets = render_obs_changes.changelog_section_to_bullets(
        "- Plain item.\n- Second item."
    )
    assert bullets == ["- Plain item.", "- Second item."]


def test_changelog_section_to_bullets_merges_nested_bullets() -> None:
    section = "\n".join(
        [
            "### Fixed",
            "",
            "- Parent item:",
            "  - nested detail.",
        ]
    )
    bullets = render_obs_changes.changelog_section_to_bullets(section)
    assert bullets == ["- Fixed: Parent item; nested detail."]


def test_changelog_section_to_bullets_wraps_continuation_lines() -> None:
    section = "\n".join(
        [
            "- Wrapped item starts",
            "  on the next line.",
        ]
    )
    bullets = render_obs_changes.changelog_section_to_bullets(section)
    assert bullets == ["- Wrapped item starts on the next line."]


def test_format_obs_timestamp_accepts_naive_datetime() -> None:
    naive = datetime(2026, 6, 7, 12, 0, 0)
    formatted = render_obs_changes.format_obs_timestamp(naive)
    assert "UTC 2026" in formatted


def test_format_obs_entry_without_bullets() -> None:
    entry = render_obs_changes.format_obs_entry(
        "1.0.0",
        [],
        "Maintainer <maintainer@example.com>",
        now=_FIXED_TIMESTAMP,
    )
    assert entry.endswith("\n\n")
    assert "\n- " not in entry


def test_version_at_top_handles_empty_and_non_separator_headers() -> None:
    assert render_obs_changes.version_at_top("", "1.0.0") is False
    assert (
        render_obs_changes.version_at_top(
            "Thu Jan  1 00:00:00 UTC 2026 - Maintainer - 1.0.0\n",
            "1.0.0",
        )
        is True
    )


def test_render_changes_raises_when_changelog_missing(tmp_path: Path) -> None:
    missing = tmp_path / "missing.md"
    with pytest.raises(FileNotFoundError, match="changelog not found"):
        render_obs_changes.render_changes(
            "1.2.3",
            missing,
            render_obs_changes.RenderChangesContext(
                maintainer="Maintainer <maintainer@example.com>",
            ),
        )


def test_render_changes_uses_seed_changes_when_no_existing_file(
    tmp_path: Path,
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")
    seed = tmp_path / "seed.changes"
    seed.write_text(_EXISTING_CHANGES, encoding="utf-8")

    output = render_obs_changes.render_changes(
        "1.2.3",
        changelog,
        render_obs_changes.RenderChangesContext(
            seed_changes_path=seed,
            maintainer="Travis Post <post.travis@gmail.com>",
            now=_FIXED_TIMESTAMP,
        ),
    )

    assert output.index(" - 1.2.3\n") < output.index(" - 1.2.2\n")


def test_parse_timestamp_supports_z_suffix_naive_and_aware_values() -> None:
    zulu = render_obs_changes._parse_timestamp("2026-06-07T12:00:00Z")
    naive = render_obs_changes._parse_timestamp("2026-06-07T12:00:00")
    aware = render_obs_changes._parse_timestamp("2026-06-07T12:00:00+05:00")

    assert zulu.tzinfo == timezone.utc
    assert naive.tzinfo == timezone.utc
    assert aware.tzinfo == timezone.utc
    assert aware.hour == 7


def test_load_obs_project_env_uses_repo_default_path() -> None:
    env = render_obs_changes.load_obs_project_env()
    assert env.obs_package == "verilyze"


def test_main_rejects_invalid_version() -> None:
    with pytest.raises(SystemExit) as exc_info:
        render_obs_changes.main(["--version", "not-semver"])
    assert exc_info.value.code == 2


def test_main_returns_error_when_changelog_section_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")

    exit_code = render_obs_changes.main(
        [
            "--version",
            "9.9.9",
            "--changelog",
            str(changelog),
            "--config",
            str(_ENV_FILE),
        ]
    )

    assert exit_code == 1
    assert "no section for version" in capsys.readouterr().err


def test_main_returns_error_when_changelog_file_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing.md"
    exit_code = render_obs_changes.main(
        [
            "--version",
            "1.2.3",
            "--changelog",
            str(missing),
            "--config",
            str(_ENV_FILE),
        ]
    )

    assert exit_code == 1
    assert "changelog not found" in capsys.readouterr().err


def test_main_writes_stdout_when_output_not_set(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")

    exit_code = render_obs_changes.main(
        [
            "--version",
            "1.2.3",
            "--changelog",
            str(changelog),
            "--config",
            str(_ENV_FILE),
            "--timestamp",
            "2026-06-07T12:00:00+00:00",
        ]
    )

    assert exit_code == 0
    assert " - 1.2.3\n" in capsys.readouterr().out


def test_main_honors_existing_and_seed_changes_flags(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")
    existing = tmp_path / "existing.changes"
    existing.write_text(_EXISTING_CHANGES, encoding="utf-8")
    seed = tmp_path / "seed.changes"
    seed.write_text("stale seed\n", encoding="utf-8")
    output_path = tmp_path / "out.changes"

    exit_code = render_obs_changes.main(
        [
            "--version",
            "1.2.3",
            "--changelog",
            str(changelog),
            "--config",
            str(_ENV_FILE),
            "--existing-changes",
            str(existing),
            "--seed-changes",
            str(seed),
            "--output",
            str(output_path),
            "--timestamp",
            "2026-06-07T12:00:00+00:00",
        ]
    )

    assert exit_code == 0
    text = output_path.read_text(encoding="utf-8")
    assert " - 1.2.3\n" in text
    assert " - 1.2.2\n" in text
    assert "stale seed" not in text


def test_main_module_exit_code(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")
    output_path = tmp_path / "out.changes"
    argv = [
        "render_obs_changes.py",
        "--version",
        "1.2.3",
        "--changelog",
        str(changelog),
        "--config",
        str(_ENV_FILE),
        "--output",
        str(output_path),
        "--timestamp",
        "2026-06-07T12:00:00+00:00",
    ]
    with patch("sys.argv", argv):
        with patch.dict(os.environ, {"PYTHONPATH": str(_ROOT)}, clear=False):
            try:
                runpy.run_path(str(_RENDER_SCRIPT), run_name="__main__")
            except SystemExit as exc:
                assert exc.code == 0
                return
    pytest.fail("Expected SystemExit from sys.exit(main())")


def test_cli_writes_output_file(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")
    output_path = tmp_path / "verilyze.changes"

    proc = subprocess.run(
        [
            sys.executable,
            str(_RENDER_SCRIPT),
            "--version",
            "1.2.3",
            "--changelog",
            str(changelog),
            "--config",
            str(_ENV_FILE),
            "--output",
            str(output_path),
            "--timestamp",
            "2026-06-07T12:00:00+00:00",
        ],
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": str(_ROOT)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    text = output_path.read_text(encoding="utf-8")
    assert " - 1.2.3\n" in text
    assert "- Fixed: First fixed item." in text
