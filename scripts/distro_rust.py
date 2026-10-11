#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Gate the workspace MSRV against Rust shipped by enabled distro targets.

Enabled targets are the OBS repositories in `packaging/obs/project/_meta`
minus package-level disables. `packaging/obs/distro-rust.toml` records, per
repository, the Rust (major.minor) the stable distro repo is known to ship and
how to probe it (OBS public API for SUSE, container for Fedora). The gate fails
when the MSRV (`[workspace.package].rust-version`) is newer than any enabled
target, so an unbuildable release is caught before the tag rather than in OBS
afterwards.

Usage (from repo root, `PYTHONPATH=.`):
  python scripts/distro_rust.py                 # offline data check
  python scripts/distro_rust.py --live          # probe OBS API / containers
  python scripts/distro_rust.py --matrix-json   # enabled targets for CI
  python scripts/distro_rust.py --canary-matrix-json  # nightly canaries
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
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET  # nosec B405

from scripts.obs_repositories import (
    DEFAULT_PROJECT_META_REL,
    load_enabled_build_repositories,
    parse_project_repository_names,
    parse_project_repository_paths,
)
from scripts.rust_version import (
    RustVersion,
    format_rust_version,
    parse_rust_version,
    read_msrv,
)

DEFAULT_DISTRO_RUST_REL = Path("packaging/obs/distro-rust.toml")
OBS_PUBLIC_BUILD_API = "https://api.opensuse.org/public/build"
PROBE_KIND_CONTAINER = "container"
PROBE_KIND_OBS = "obs"
_PROBE_KINDS = frozenset({PROBE_KIND_CONTAINER, PROBE_KIND_OBS})

_VERSION_IN_TEXT = re.compile(r"(\d+)\.(\d+)(?:\.\d+)?")
_VERSIONED_RUST_PACKAGE = re.compile(r"^rust(\d+)\.(\d+)$")
_HTTP_USER_AGENT = "verilyze-distro-rust-probe/1.0"

ProbeRunner = Callable[["DistroTarget"], str]
HttpFetcher = Callable[[str], str]


@dataclass(frozen=True)
class DistroTarget:  # pylint: disable=too-many-instance-attributes
    """One OBS build repository and how to check its Rust version."""

    repository: str
    distro: str
    rust_available: RustVersion | None
    verified_at: str
    probe_kind: str
    obs_project: str | None
    obs_repository: str | None
    probe_image: str
    probe_command: str
    build_deps_command: str
    disabled_reason: str | None


@dataclass(frozen=True)
class CanaryTarget:
    """Non-OBS (or advisory) distro canary for nightly builds."""

    name: str
    distro: str
    probe_image: str
    build_deps_command: str


def _required_str(
    section: str, name: str, table: dict[str, object], key: str
) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        msg = f"{section}.{name}.{key} is required in distro-rust.toml"
        raise ValueError(msg)
    return value


def _optional_str(table: dict[str, object], key: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        msg = f"{key} must be a non-empty string when set"
        raise ValueError(msg)
    return value


def _parse_probe_kind(repository: str, table: dict[str, object]) -> str:
    raw = table.get("probe_kind", PROBE_KIND_CONTAINER)
    if not isinstance(raw, str) or raw not in _PROBE_KINDS:
        msg = (
            f"targets.{repository}.probe_kind must be one of "
            f"{sorted(_PROBE_KINDS)}"
        )
        raise ValueError(msg)
    return raw


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
            distro=_required_str("targets", repository, table, "distro"),
            rust_available=(
                parse_rust_version(available)
                if isinstance(available, str)
                else None
            ),
            verified_at=_required_str(
                "targets", repository, table, "verified_at"
            ),
            probe_kind=_parse_probe_kind(repository, table),
            obs_project=_optional_str(table, "obs_project"),
            obs_repository=_optional_str(table, "obs_repository"),
            probe_image=_required_str(
                "targets", repository, table, "probe_image"
            ),
            probe_command=_required_str(
                "targets", repository, table, "probe_command"
            ),
            build_deps_command=_required_str(
                "targets", repository, table, "build_deps_command"
            ),
            disabled_reason=disabled if isinstance(disabled, str) else None,
        )
    return targets


def parse_canary_targets(text: str) -> dict[str, CanaryTarget]:
    """Parse optional [canaries.*] rows (non-OBS nightly advisory builds)."""
    data = tomllib.loads(text)
    tables = data.get("canaries")
    if tables is None:
        return {}
    if not isinstance(tables, dict):
        msg = "distro-rust.toml [canaries] must be a table"
        raise ValueError(msg)
    canaries: dict[str, CanaryTarget] = {}
    for name, table in tables.items():
        if not isinstance(table, dict):
            msg = f"canaries.{name} must be a table"
            raise ValueError(msg)
        canaries[name] = CanaryTarget(
            name=name,
            distro=_required_str("canaries", name, table, "distro"),
            probe_image=_required_str("canaries", name, table, "probe_image"),
            build_deps_command=_required_str(
                "canaries", name, table, "build_deps_command"
            ),
        )
    return canaries


def load_distro_targets(repo_root: Path) -> dict[str, DistroTarget]:
    """Load distro-rust.toml from the repository."""
    path = repo_root / DEFAULT_DISTRO_RUST_REL
    if not path.is_file():
        msg = f"distro-rust data not found: {path}"
        raise FileNotFoundError(msg)
    return parse_distro_targets(path.read_text(encoding="utf-8"))


def load_canary_targets(repo_root: Path) -> dict[str, CanaryTarget]:
    """Load [canaries.*] from distro-rust.toml."""
    path = repo_root / DEFAULT_DISTRO_RUST_REL
    if not path.is_file():
        msg = f"distro-rust data not found: {path}"
        raise FileNotFoundError(msg)
    return parse_canary_targets(path.read_text(encoding="utf-8"))


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


def build_canary_matrix(repo_root: Path) -> list[dict[str, str]]:
    """Return nightly canary rows: disabled OBS targets plus [canaries.*]."""
    targets = load_distro_targets(repo_root)
    enabled = frozenset(load_enabled_build_repositories(repo_root))
    rows: list[dict[str, str]] = []
    for repository in sorted(targets):
        target = targets[repository]
        if repository in enabled or not target.disabled_reason:
            continue
        rows.append(
            {
                "name": repository,
                "distro": target.distro,
                "image": target.probe_image,
                "deps_command": target.build_deps_command,
            }
        )
    canaries = load_canary_targets(repo_root)
    for name in sorted(canaries):
        canary = canaries[name]
        rows.append(
            {
                "name": canary.name,
                "distro": canary.distro,
                "image": canary.probe_image,
                "deps_command": canary.build_deps_command,
            }
        )
    return rows


def extract_rust_version(output: str) -> RustVersion | None:
    """Return the first major.minor found in probe output, or None."""
    match = _VERSION_IN_TEXT.search(output)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def versioned_rust_package_name(version: RustVersion) -> str:
    """Return the openSUSE versioned rust package name for major.minor."""
    return f"rust{version[0]}.{version[1]}"


def parse_versioned_rust_package_name(name: str) -> RustVersion | None:
    """Parse `rust1.98` package names; ignore variants like `rust1.98:test`."""
    match = _VERSIONED_RUST_PACKAGE.fullmatch(name)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def highest_versioned_rust_package(entries: tuple[str, ...]) -> RustVersion | None:
    """Return the highest rustX.Y package name from a directory listing."""
    versions = [
        parsed
        for name in entries
        if (parsed := parse_versioned_rust_package_name(name)) is not None
    ]
    return max(versions) if versions else None


def parse_binarylist_filenames(xml_text: str) -> frozenset[str]:
    """Return RPM filenames from an OBS public binarylist response."""
    try:
        root = ET.fromstring(xml_text)  # nosec B314
    except ET.ParseError as exc:
        msg = f"OBS binarylist XML is not well-formed: {exc}"
        raise ValueError(msg) from exc
    if root.tag != "binarylist":
        msg = f"expected <binarylist>, got <{root.tag}>"
        raise ValueError(msg)
    names = frozenset(
        name
        for binary in root.findall("binary")
        if (name := (binary.get("filename") or "").strip())
        and not name.startswith("_")
        and name != "rpmlint.log"
    )
    if not names:
        msg = "empty binarylist"
        raise ValueError(msg)
    return names


def parse_directory_entry_names(xml_text: str) -> tuple[str, ...]:
    """Return entry names from an OBS public build directory listing."""
    try:
        root = ET.fromstring(xml_text)  # nosec B314
    except ET.ParseError as exc:
        msg = f"OBS directory XML is not well-formed: {exc}"
        raise ValueError(msg) from exc
    if root.tag == "status":
        summary = (root.findtext("summary") or root.get("code") or "").strip()
        msg = f"OBS build API error: {summary or xml_text.strip()}"
        raise ValueError(msg)
    if root.tag != "directory":
        msg = f"expected <directory>, got <{root.tag}>"
        raise ValueError(msg)
    return tuple(
        name
        for entry in root.findall("entry")
        if (name := (entry.get("name") or "").strip())
    )


def obs_binarylist_has_msrv_packages(
    filenames: frozenset[str], msrv: RustVersion
) -> bool:
    """True when binarylist has rustX.Y and cargoX.Y RPMs for the MSRV."""
    major, minor = msrv
    rust_prefix = f"rust{major}.{minor}-"
    cargo_prefix = f"cargo{major}.{minor}-"
    has_rust = any(
        name.startswith(rust_prefix) and name.endswith(".rpm")
        for name in filenames
    )
    has_cargo = any(
        name.startswith(cargo_prefix) and name.endswith(".rpm")
        for name in filenames
    )
    return has_rust and has_cargo


def default_http_fetcher(url: str) -> str:
    """GET a URL and return the response body as text (fail closed)."""
    request = urllib.request.Request(  # nosec B310
        url,
        headers={"User-Agent": _HTTP_USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        msg = f"HTTP {exc.code} for {url}: {body.strip() or exc.reason}"
        raise RuntimeError(msg) from exc
    except urllib.error.URLError as exc:
        msg = f"HTTP error for {url}: {exc.reason}"
        raise RuntimeError(msg) from exc


def _obs_build_base(
    target: DistroTarget, path_project: str, path_repo: str
) -> str:
    project = target.obs_project or path_project
    repository = target.obs_repository or path_repo
    return f"{OBS_PUBLIC_BUILD_API}/{project}/{repository}"


def obs_probe_target(
    repo_root: Path,
    target: DistroTarget,
    *,
    msrv: RustVersion,
    fetcher: HttpFetcher,
) -> RustVersion:
    """Probe OBS for versioned rust/cargo packages and the highest rustX.Y."""
    meta = (repo_root / DEFAULT_PROJECT_META_REL).read_text(encoding="utf-8")
    paths = parse_project_repository_paths(meta)
    path = paths.get(target.repository)
    if path is None:
        msg = (
            f"OBS path for {target.repository!r} missing from project _meta"
        )
        raise ValueError(msg)
    base = _obs_build_base(target, path.project, path.repository)
    package = versioned_rust_package_name(msrv)
    per_arch: list[RustVersion] = []
    for arch in path.arches:
        listing = parse_directory_entry_names(fetcher(f"{base}/{arch}"))
        highest = highest_versioned_rust_package(listing)
        if highest is None:
            msg = (
                f"OBS probe for {target.repository} ({arch}): no rustX.Y "
                f"packages under {base}/{arch}"
            )
            raise ValueError(msg)
        binary_xml = fetcher(f"{base}/{arch}/{package}")
        try:
            filenames = parse_binarylist_filenames(binary_xml)
        except ValueError as exc:
            msg = (
                f"OBS probe for {target.repository} ({arch}): "
                f"{package} missing or empty ({exc})"
            )
            raise ValueError(msg) from exc
        if not obs_binarylist_has_msrv_packages(filenames, msrv):
            msg = (
                f"OBS probe for {target.repository} ({arch}): {package} "
                f"lacks rust{msrv[0]}.{msrv[1]} and cargo{msrv[0]}.{msrv[1]} "
                "RPMs"
            )
            raise ValueError(msg)
        per_arch.append(highest)
    if len(set(per_arch)) != 1:
        formatted = ", ".join(
            f"{arch}={format_rust_version(ver)}"
            for arch, ver in zip(path.arches, per_arch, strict=True)
        )
        msg = (
            f"OBS probe for {target.repository}: architectures disagree "
            f"({formatted})"
        )
        raise ValueError(msg)
    return per_arch[0]


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


def _evaluate_probed_version(
    target: DistroTarget,
    probed: RustVersion,
    msrv: RustVersion,
) -> tuple[list[str], list[str]]:
    """Compare a live probe to MSRV and committed rust_available."""
    errors: list[str] = []
    notes: list[str] = []
    if msrv > probed:
        errors.append(
            f"live probe: {target.distro} ({target.repository}) ships Rust "
            f"{format_rust_version(probed)}, below MSRV "
            f"{format_rust_version(msrv)}"
        )
    if target.rust_available is not None and probed < target.rust_available:
        errors.append(
            f"live probe: {target.distro} ({target.repository}) ships Rust "
            f"{format_rust_version(probed)}, below committed rust_available "
            f"{format_rust_version(target.rust_available)}"
        )
    if target.rust_available is not None and probed > target.rust_available:
        notes.append(
            f"live probe: {target.distro} ({target.repository}) ships Rust "
            f"{format_rust_version(probed)}; can raise rust_available from "
            f"{format_rust_version(target.rust_available)}"
        )
    return errors, notes


def check_live(
    repo_root: Path,
    runner: ProbeRunner,
    *,
    http_fetcher: HttpFetcher | None = None,
) -> tuple[list[str], list[str]]:
    """Probe each enabled target; return (errors, raise-rust_available notes)."""
    msrv = read_msrv(repo_root)
    targets = load_distro_targets(repo_root)
    fetcher = http_fetcher or default_http_fetcher
    errors: list[str] = []
    notes: list[str] = []
    for repository in load_enabled_build_repositories(repo_root):
        target = targets.get(repository)
        if target is None:
            continue
        try:
            if target.probe_kind == PROBE_KIND_OBS:
                probed = obs_probe_target(
                    repo_root, target, msrv=msrv, fetcher=fetcher
                )
            else:
                probed = probe_target(target, runner)
        except (RuntimeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        target_errors, target_notes = _evaluate_probed_version(
            target, probed, msrv
        )
        errors.extend(target_errors)
        notes.extend(target_notes)
    return errors, notes


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
        help="Also probe each enabled distro (OBS API and/or containers)",
    )
    parser.add_argument(
        "--matrix-json",
        action="store_true",
        help="Print GitHub Actions matrix JSON for enabled targets and exit",
    )
    parser.add_argument(
        "--canary-matrix-json",
        action="store_true",
        help="Print GitHub Actions matrix JSON for nightly canaries and exit",
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

    if args.canary_matrix_json:
        try:
            rows = build_canary_matrix(args.repo_root)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"include": rows}))
        return 0

    notes: list[str] = []
    try:
        errors = check_distro_rust(args.repo_root)
        if args.live and not errors:
            errors, notes = check_live(args.repo_root, docker_probe_runner)
    except (FileNotFoundError, ValueError) as exc:
        errors = [str(exc)]

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"NOTE: {note}")
    msrv = format_rust_version(read_msrv(args.repo_root))
    scope = "live probe" if args.live else "committed data"
    print(
        f"check-distro-rust: MSRV {msrv} fits enabled distro targets "
        f"({scope})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
