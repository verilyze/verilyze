#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Render OBS RPM .changes entries from CHANGELOG.md release sections."""

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scripts.obs_project_env import ObsProjectEnv, parse_obs_project_env

MAX_BULLETS = 15
TRUNCATION_NOTE = "- See upstream CHANGELOG.md for full details."
ENTRY_SEPARATOR = (
    "-------------------------------------------------------------------"
)
RELEASE_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
SECTION_HEADING_RE = re.compile(r"^## \[([^\]]+)\]")
CATEGORY_HEADING_RE = re.compile(r"^### (.+)$")
BULLET_RE = re.compile(r"^(\s*)- (.+)$")
DEFAULT_OBS_ENV = Path("packaging/obs/obs-project.env")


class ChangelogSectionNotFoundError(RuntimeError):
    """Raised when CHANGELOG.md has no section for the requested version."""


@dataclass(frozen=True)
class RenderChangesContext:
    """Optional inputs for rendering OBS .changes content."""

    existing_changes_path: Path | None = None
    seed_changes_path: Path | None = None
    maintainer: str | None = None
    config_path: Path | None = None
    now: datetime | None = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_obs_project_env(config_path: Path | None = None) -> ObsProjectEnv:
    """Load OBS constants from obs-project.env."""
    path = config_path or (_repo_root() / DEFAULT_OBS_ENV)
    return parse_obs_project_env(path)


def validate_release_version(version: str) -> None:
    """Exit with code 2 when version is not Cargo-style SemVer."""
    if not RELEASE_SEMVER_RE.fullmatch(version):
        print(
            "error: version must be SemVer (Cargo-style), "
            "without a leading v prefix.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def extract_changelog_section(changelog_text: str, version: str) -> str:
    """Return the body of the matching ## [version] section."""
    lines = changelog_text.splitlines()
    found = False
    section_lines: list[str] = []

    for line in lines:
        if SECTION_HEADING_RE.match(line):
            if found:
                break
            if line.startswith(f"## [{version}]"):
                found = True
                continue
            continue
        if found:
            section_lines.append(line)

    if not found:
        raise ChangelogSectionNotFoundError(
            f"CHANGELOG.md has no section for version {version}"
        )
    return "\n".join(section_lines).strip("\n")


def changelog_section_to_bullets(section_text: str) -> list[str]:
    """Flatten Keep-a-Changelog-style section text into OBS bullet lines."""
    bullets: list[str] = []
    current_category = ""

    for raw_line in section_text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue

        category_match = CATEGORY_HEADING_RE.match(line)
        if category_match:
            current_category = category_match.group(1).strip()
            continue

        bullet_match = BULLET_RE.match(line)
        if bullet_match:
            indent, text = bullet_match.groups()
            text = text.strip()
            if not text:
                continue

            if indent:
                if bullets:
                    parent = bullets[-1].rstrip(":")
                    bullets[-1] = f"{parent}; {text}"
                continue

            if current_category:
                bullets.append(f"- {current_category}: {text}")
            else:
                bullets.append(f"- {text}")
            continue

        if bullets and line[:1].isspace():
            bullets[-1] = f"{bullets[-1]} {line.strip()}"

    if len(bullets) > MAX_BULLETS:
        bullets = bullets[: MAX_BULLETS - 1]
        bullets.append(TRUNCATION_NOTE)
    return bullets


def format_obs_timestamp(now: datetime) -> str:
    """Format a UTC timestamp for OBS .changes entry headers."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    # OBS/openSUSE .changes uses a space-padded day without a leading zero.
    return (
        f"{now.strftime('%a %b ')}{now.day:2d}"
        f"{now.strftime(' %H:%M:%S UTC %Y')}"
    )


def format_obs_entry(
    version: str,
    bullets: list[str],
    maintainer: str,
    *,
    now: datetime | None = None,
) -> str:
    """Render one OBS .changes entry."""
    timestamp = format_obs_timestamp(now or datetime.now(timezone.utc))
    header = f"{ENTRY_SEPARATOR}\n{timestamp} - {maintainer} - {version}\n"
    body = "\n".join(bullets)
    if body:
        return f"{header}\n{body}\n"
    return f"{header}\n"


def version_at_top(changes_text: str, version: str) -> bool:
    """Return True when the newest .changes entry already documents version."""
    stripped = changes_text.lstrip("\n")
    if not stripped:
        return False
    first_entry = stripped.split(f"{ENTRY_SEPARATOR}\n", 2)
    if stripped.startswith(ENTRY_SEPARATOR):
        header_block = first_entry[1] if len(first_entry) > 1 else ""
    else:
        header_block = first_entry[0]
    for line in header_block.splitlines():
        if line.endswith(f" - {version}"):
            return True
    return False


def render_changes(
    version: str,
    changelog_path: Path,
    context: RenderChangesContext | None = None,
) -> str:
    """Build OBS .changes content for one release version."""
    ctx = context or RenderChangesContext()
    validate_release_version(version)

    maintainer = ctx.maintainer
    if maintainer is None:
        maintainer = load_obs_project_env(ctx.config_path).obs_maintainer

    if not changelog_path.is_file():
        raise FileNotFoundError(f"changelog not found: {changelog_path}")

    section = extract_changelog_section(
        changelog_path.read_text(encoding="utf-8"),
        version,
    )
    entry = format_obs_entry(
        version,
        changelog_section_to_bullets(section),
        maintainer,
        now=ctx.now,
    )

    existing_text = ""
    if ctx.existing_changes_path and ctx.existing_changes_path.is_file():
        existing_text = ctx.existing_changes_path.read_text(encoding="utf-8")
    elif ctx.seed_changes_path and ctx.seed_changes_path.is_file():
        existing_text = ctx.seed_changes_path.read_text(encoding="utf-8")

    if existing_text and version_at_top(existing_text, version):
        return existing_text

    if existing_text.strip():
        return f"{entry.rstrip()}\n\n{existing_text.lstrip()}"
    return entry


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp for deterministic tests."""
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Render OBS .changes content from CHANGELOG.md.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Release version X.Y.Z",
    )
    parser.add_argument(
        "--changelog",
        default=str(_repo_root() / "CHANGELOG.md"),
        help="Path to CHANGELOG.md",
    )
    parser.add_argument(
        "--config",
        default=str(_repo_root() / DEFAULT_OBS_ENV),
        help="Path to obs-project.env",
    )
    parser.add_argument(
        "--existing-changes",
        help="Existing OBS .changes file to prepend to",
    )
    parser.add_argument(
        "--seed-changes",
        help="Seed .changes template when no existing file is available",
    )
    parser.add_argument(
        "--output",
        help="Write rendered .changes to this path (default: stdout)",
    )
    parser.add_argument(
        "--timestamp",
        help="Fixed UTC timestamp for tests (ISO-8601)",
    )
    args = parser.parse_args(argv)

    validate_release_version(args.version)
    now = _parse_timestamp(args.timestamp) if args.timestamp else None

    try:
        rendered = render_changes(
            args.version,
            Path(args.changelog),
            RenderChangesContext(
                existing_changes_path=(
                    Path(args.existing_changes)
                    if args.existing_changes
                    else None
                ),
                seed_changes_path=(
                    Path(args.seed_changes) if args.seed_changes else None
                ),
                config_path=Path(args.config),
                now=now,
            ),
        )
    except ChangelogSectionNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
