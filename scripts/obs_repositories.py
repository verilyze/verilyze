#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Derive OBS enabled build repositories from committed _meta files."""

import argparse
from pathlib import Path
import sys
import xml.etree.ElementTree as ET  # nosec B405

DEFAULT_PROJECT_META_REL = Path("packaging/obs/project/_meta")
DEFAULT_PACKAGE_META_REL = Path("packaging/obs/rpm/_meta")


def parse_project_repository_names(project_meta_xml: str) -> tuple[str, ...]:
    """Return sorted unique repository names from OBS project _meta XML."""
    root = ET.fromstring(project_meta_xml)  # nosec B314
    names: set[str] = set()
    for repository in root.findall("repository"):
        name = (repository.get("name") or "").strip()
        if name:
            names.add(name)
    if not names:
        msg = "OBS project _meta contains no repository definitions"
        raise ValueError(msg)
    return tuple(sorted(names))


def parse_package_disabled_repositories(
    package_meta_xml: str,
) -> frozenset[str]:
    """Return repository names disabled for builds in package _meta XML."""
    root = ET.fromstring(package_meta_xml)  # nosec B314
    disabled: set[str] = set()
    build = root.find("build")
    if build is None:
        return frozenset()
    for flag in build.findall("disable"):
        repository = (flag.get("repository") or "").strip()
        if repository:
            disabled.add(repository)
    return frozenset(disabled)


def enabled_build_repositories(
    project_meta_xml: str,
    package_meta_xml: str,
) -> tuple[str, ...]:
    """Return enabled build repository names for the package."""
    project_repos = parse_project_repository_names(project_meta_xml)
    disabled = parse_package_disabled_repositories(package_meta_xml)
    return tuple(name for name in project_repos if name not in disabled)


def load_enabled_build_repositories(
    repo_root: Path,
    *,
    project_meta_path: Path | None = None,
    package_meta_path: Path | None = None,
) -> tuple[str, ...]:
    """Load and derive enabled repositories from committed _meta files."""
    project_path = project_meta_path or (repo_root / DEFAULT_PROJECT_META_REL)
    package_path = package_meta_path or (repo_root / DEFAULT_PACKAGE_META_REL)
    if not project_path.is_file():
        msg = f"OBS project _meta not found: {project_path}"
        raise FileNotFoundError(msg)
    if not package_path.is_file():
        msg = f"OBS package _meta not found: {package_path}"
        raise FileNotFoundError(msg)
    project_meta_xml = project_path.read_text(encoding="utf-8")
    package_meta_xml = package_path.read_text(encoding="utf-8")
    return enabled_build_repositories(project_meta_xml, package_meta_xml)


def format_repository_list(repositories: tuple[str, ...]) -> str:
    """Format repository names as a comma-separated list for shell scripts."""
    return ",".join(repositories)


def main() -> int:
    """CLI entry point for shell integration."""
    parser = argparse.ArgumentParser(
        description="Derive enabled OBS build repositories from _meta files.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--project-meta",
        type=Path,
        help=(
            "Override path to project _meta "
            "(default: packaging/obs/project/_meta)"
        ),
    )
    parser.add_argument(
        "--package-meta",
        type=Path,
        help=(
            "Override path to package _meta "
            "(default: packaging/obs/rpm/_meta)"
        ),
    )
    args = parser.parse_args()
    repositories = load_enabled_build_repositories(
        args.repo_root,
        project_meta_path=args.project_meta,
        package_meta_path=args.package_meta,
    )
    sys.stdout.write(format_repository_list(repositories))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
