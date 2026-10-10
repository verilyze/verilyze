#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Gate the workspace MSRV against Rust shipped by enabled distro targets.

Enabled targets are the OBS repositories in `packaging/obs/project/_meta`
minus package-level disables. `packaging/obs/distro-rust.toml` records, per
repository, the Rust (major.minor) the stable distro repo is known to ship and
how to probe it in a container. The gate fails when the MSRV
(`[workspace.package].rust-version`) is newer than any enabled target, so an
unbuildable release is caught before the tag rather than in OBS afterwards.

Usage (from repo root, `PYTHONPATH=.`):
  python scripts/distro_rust.py          # offline data check
  python scripts/distro_rust.py --live   # also probe distro containers
  python scripts/distro_rust.py --matrix-json  # enabled targets for CI
"""

import argparse
from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess  # nosec B404
import sys
import tomllib

from scripts.obs_repositories import (
    DEFAULT_PROJECT_META_REL,
    load_enabled_build_repositories,
    parse_project_repository_names,
)
from scripts.rust_version import (
    RustVersion,
    format_rust_version,
    parse_rust_version,
    read_msrv,
)

DEFAULT_DISTRO_RUST_REL = Path("packaging/obs/distro-rust.toml")

_VERSION_IN_TEXT = re.compile(r"(\d+)\.(\d+)(?:\.\d+)?")

ProbeRunner = Callable[["DistroTarget"], str]


@dataclass(frozen=True)
class DistroTarget:  # pylint: disable=too-many-instance-attributes
    """One OBS build repository and how to check its Rust version."""

    repository: str
    distro: str
    rust_available: RustVersion | None
    verified_at: str
    probe_image: str
    probe_command: str
    build_deps_command: str
    disabled_reason: str | None


def _required_str(repository: str, table: dict[str, object], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        msg = f"targets.{repository}.{key} is required in distro-rust.toml"
        raise ValueError(msg)
    return value


def parse_distro_targets(text: str) -> dict[str, DistroTarget]:
    """Parse distro-rust.toml into targets keyed by OBS repository name."""
    data = tomllib.loads(text)
    tables = data.get("targets")
    if not isinstance(tables, dict) or not tables:
        msg = "distro-rust.toml must define a [targets] table"
        raise ValueError(msg)
    targets: dict[str, DistroTarget] = {}
    for repository, table in tables.items():
        if not isinstance(table, dict):
            msg = f"targets.{repository} must be a table"
            raise ValueError(msg)
        available = table.get("rust_available")
        disabled = table.get("disabled_reason")
        targets[repository] = DistroTarget(
            repository=repository,
            distro=_required_str(repository, table, "distro"),
            rust_available=(
                parse_rust_version(available)
                if isinstance(available, str)
                else None
            ),
            verified_at=_required_str(repository, table, "verified_at"),
            probe_image=_required_str(repository, table, "probe_image"),
            probe_command=_required_str(repository, table, "probe_command"),
            build_deps_command=_required_str(
                repository, table, "build_deps_command"
            ),
            disabled_reason=disabled if isinstance(disabled, str) else None,
        )
    return targets


def load_distro_targets(repo_root: Path) -> dict[str, DistroTarget]:
    """Load distro-rust.toml from the repository."""
    path = repo_root / DEFAULT_DISTRO_RUST_REL
    if not path.is_file():
        msg = f"distro-rust data not found: {path}"
        raise FileNotFoundError(msg)
    return parse_distro_targets(path.read_text(encoding="utf-8"))


def _project_repository_names(repo_root: Path) -> frozenset[str]:
    meta = (repo_root / DEFAULT_PROJECT_META_REL).read_text(encoding="utf-8")
    return frozenset(parse_project_repository_names(meta))


def check_distro_rust(repo_root: Path) -> list[str]:
    """Return errors when the MSRV exceeds Rust on any enabled target."""
    msrv = read_msrv(repo_root)
    targets = load_distro_targets(repo_root)
    enabled = load_enabled_build_repositories(repo_root)
    errors: list[str] = []

    known = _project_repository_names(repo_root)
    for repository in sorted(targets):
        if repository not in known:
            errors.append(
                f"distro-rust.toml target {repository!r} is not a repository "
                "in the OBS project _meta"
            )

    for repository in enabled:
        target = targets.get(repository)
        if target is None:
            errors.append(
                f"enabled OBS repository {repository!r} has no entry in "
                f"{DEFAULT_DISTRO_RUST_REL}"
            )
            continue
        if target.rust_available is None:
            errors.append(
                f"targets.{repository}.rust_available is required for an "
                "enabled OBS repository"
            )
            continue
        if msrv > target.rust_available:
            errors.append(
                f"MSRV {format_rust_version(msrv)} is newer than Rust "
                f"{format_rust_version(target.rust_available)} on "
                f"{target.distro} ({repository}); lower rust-version, wait "
                "for the distro, or disable the target in the OBS _meta"
            )
    return errors


def build_matrix(repo_root: Path) -> list[dict[str, str]]:
    """Return one CI matrix row per enabled target (distro build workflow)."""
    targets = load_distro_targets(repo_root)
    rows: list[dict[str, str]] = []
    for repository in load_enabled_build_repositories(repo_root):
        target = targets.get(repository)
        if target is None:
            continue
        rows.append(
            {
                "repository": repository,
                "distro": target.distro,
                "image": target.probe_image,
                "deps_command": target.build_deps_command,
            }
        )
    return rows


def extract_rust_version(output: str) -> RustVersion | None:
    """Return the first major.minor found in probe output, or None."""
    match = _VERSION_IN_TEXT.search(output)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def docker_probe_runner(target: DistroTarget) -> str:
    """Run the target's probe command in its container image."""
    result = subprocess.run(  # nosec B603 B607
        [
            "docker",
            "run",
            "--rm",
            target.probe_image,
            "sh",
            "-c",
            target.probe_command,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        msg = (
            f"probe for {target.repository} failed "
            f"(exit {result.returncode}): {result.stderr.strip()}"
        )
        raise RuntimeError(msg)
    return result.stdout


def probe_target(target: DistroTarget, runner: ProbeRunner) -> RustVersion:
    """Return the Rust (major.minor) the target's repo currently ships."""
    version = extract_rust_version(runner(target))
    if version is None:
        msg = f"probe for {target.repository} printed no Rust version"
        raise ValueError(msg)
    return version


def check_live(repo_root: Path, runner: ProbeRunner) -> list[str]:
    """Probe each enabled target and compare the result to the MSRV."""
    msrv = read_msrv(repo_root)
    targets = load_distro_targets(repo_root)
    errors: list[str] = []
    for repository in load_enabled_build_repositories(repo_root):
        target = targets.get(repository)
        if target is None:
            continue
        try:
            probed = probe_target(target, runner)
        except (RuntimeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        if msrv > probed:
            errors.append(
                f"live probe: {target.distro} ({repository}) ships Rust "
                f"{format_rust_version(probed)}, below MSRV "
                f"{format_rust_version(msrv)}"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (default: parent of scripts/)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Also probe each enabled distro container (needs Docker)",
    )
    parser.add_argument(
        "--matrix-json",
        action="store_true",
        help="Print GitHub Actions matrix JSON for enabled targets and exit",
    )
    args = parser.parse_args(argv)

    if args.matrix_json:
        try:
            rows = build_matrix(args.repo_root)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"include": rows}))
        return 0

    try:
        errors = check_distro_rust(args.repo_root)
        if args.live and not errors:
            errors = check_live(args.repo_root, docker_probe_runner)
    except (FileNotFoundError, ValueError) as exc:
        errors = [str(exc)]

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    msrv = format_rust_version(read_msrv(args.repo_root))
    scope = "live probe" if args.live else "committed data"
    print(
        f"check-distro-rust: MSRV {msrv} fits enabled distro targets "
        f"({scope})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
