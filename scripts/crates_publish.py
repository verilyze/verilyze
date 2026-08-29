#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""crates.io publish order and manifest validation."""

import argparse
import os
import re
import subprocess  # nosec B404
import sys
import tomllib
from collections import deque
from pathlib import Path

# Production crates published to crates.io (fuzz crates excluded).
PUBLISHED_CRATE_NAMES: tuple[str, ...] = (
    "vlz-db",
    "vlz-manifest-finder",
    "vlz-plugin-macro",
    "vlz-reachability-trait",
    "vlz-manifest-parser",
    "vlz-cve-client",
    "vlz-report",
    "vlz-integrity",
    "vlz-reachability",
    "vlz-python",
    "vlz-rust",
    "vlz-go",
    "vlz-javascript",
    "vlz-java",
    "vlz-ruby",
    "vlz-cve-provider-nvd",
    "vlz-cve-provider-github",
    "vlz-cve-provider-sonatype",
    "vlz-db-redb",
    "vlz-db-mem",
    "vlz",
)

WORKSPACE_INTERNAL_DEP_RE = re.compile(
    r"^vlz-(?:db|manifest-finder|manifest-parser|reachability-trait|"
    r"reachability|cve-client|report|integrity|plugin-macro|python|rust|go|"
    r"javascript|java|ruby|cve-provider-nvd|cve-provider-github|"
    r"cve-provider-sonatype|db-redb|db-mem)$"
)

VLZ_INSTALL_BINARIES = frozenset({"vlz"})
REGISTRY_INHERIT_FIELDS = ("keywords", "categories", "readme", "rust-version")


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def read_workspace_version(cargo_toml: Path) -> str:
    """Read [workspace.package].version from the root Cargo.toml."""
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    version = data["workspace"]["package"]["version"]
    if not isinstance(version, str):
        msg = f"invalid workspace version in {cargo_toml}"
        raise ValueError(msg)
    return version


def discover_crate_manifests(repo_root: Path) -> dict[str, Path]:
    """Map published crate name -> Cargo.toml path under crates/."""
    manifests: dict[str, Path] = {}
    for manifest in sorted((repo_root / "crates").rglob("Cargo.toml")):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        name = data.get("package", {}).get("name")
        if not isinstance(name, str):
            continue
        if name in PUBLISHED_CRATE_NAMES:
            manifests[name] = manifest
    missing = [name for name in PUBLISHED_CRATE_NAMES if name not in manifests]
    if missing:
        msg = f"missing Cargo.toml for published crates: {', '.join(missing)}"
        raise ValueError(msg)
    return manifests


def parse_internal_dependencies(manifest_path: Path) -> set[str]:
    """Return workspace-internal dependency names declared in a manifest."""
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    deps: set[str] = set()
    for section in ("dependencies", "build-dependencies"):
        table = data.get(section, {})
        if not isinstance(table, dict):
            continue
        for dep_name in table:
            if WORKSPACE_INTERNAL_DEP_RE.match(dep_name):
                deps.add(dep_name)
    return deps


def publish_order(manifests: dict[str, Path]) -> list[str]:
    """Topological sort: dependencies before dependents."""
    internal_deps = {
        name: parse_internal_dependencies(path)
        for name, path in manifests.items()
    }
    in_degree = {name: 0 for name in manifests}
    dependents: dict[str, list[str]] = {name: [] for name in manifests}
    for name, deps in internal_deps.items():
        for dep in deps:
            if dep not in manifests:
                msg = f"{name} depends on unknown crate {dep}"
                raise ValueError(msg)
            in_degree[name] += 1
            dependents[dep].append(name)

    queue: deque[str] = deque(
        sorted(name for name, degree in in_degree.items() if degree == 0)
    )
    ordered: list[str] = []
    while queue:
        current = queue.popleft()
        ordered.append(current)
        for child in sorted(dependents[current]):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    if len(ordered) != len(manifests):
        msg = "cycle detected in workspace crate dependency graph"
        raise ValueError(msg)
    return ordered


def workspace_internal_dep_versions(cargo_toml: Path) -> dict[str, str]:
    """Return workspace dependency name -> version from root Cargo.toml."""
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    deps = data.get("workspace", {}).get("dependencies", {})
    versions: dict[str, str] = {}
    if not isinstance(deps, dict):
        return versions
    for name, spec in deps.items():
        if not WORKSPACE_INTERNAL_DEP_RE.match(name):
            continue
        if isinstance(spec, dict):
            version = spec.get("version")
            if isinstance(version, str):
                versions[name] = version
    return versions


def validate_workspace_dep_versions(repo_root: Path) -> list[str]:
    """Ensure internal dep versions match workspace.package.version."""
    cargo_toml = repo_root / "Cargo.toml"
    workspace_version = read_workspace_version(cargo_toml)
    dep_versions = workspace_internal_dep_versions(cargo_toml)
    errors: list[str] = []
    for name, version in sorted(dep_versions.items()):
        if version != workspace_version:
            errors.append(
                f"workspace.dependencies.{name}.version is {version!r}, "
                f"expected {workspace_version!r}"
            )
    return errors


def inherits_workspace_field(package: dict[str, object], field: str) -> bool:
    """Return True when package.<field> is inherited from the workspace."""
    value = package.get(field)
    return isinstance(value, dict) and value.get("workspace") is True


def rust_version_from_toolchain_channel(channel: str) -> str:
    """Map rust-toolchain.toml channel to Cargo rust-version (major.minor)."""
    parts = channel.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{parts[0]}.{parts[1]}"
    return channel


def read_workspace_package_table(cargo_toml: Path) -> dict[str, object]:
    """Return [workspace.package] from the root Cargo.toml."""
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    package = data.get("workspace", {}).get("package", {})
    if isinstance(package, dict):
        return package
    return {}


def validate_workspace_rust_version(
    repo_root: Path, workspace_package: dict[str, object]
) -> list[str]:
    """Keep workspace rust-version aligned with rust-toolchain.toml."""
    toolchain_path = repo_root / "rust-toolchain.toml"
    if not toolchain_path.is_file():
        return []
    toolchain = tomllib.loads(toolchain_path.read_text(encoding="utf-8"))
    channel = toolchain.get("toolchain", {}).get("channel")
    if not isinstance(channel, str):
        return []
    expected = rust_version_from_toolchain_channel(channel)
    actual = workspace_package.get("rust-version")
    if actual == expected:
        return []
    return [
        "workspace.package.rust-version is "
        f"{actual!r}, expected {expected!r} from toolchain {channel!r}"
    ]


def validate_registry_metadata(
    repo_root: Path, manifests: dict[str, Path]
) -> list[str]:
    """Ensure published crates inherit crates.io discovery metadata."""
    errors: list[str] = []
    workspace_package = read_workspace_package_table(repo_root / "Cargo.toml")
    for field in REGISTRY_INHERIT_FIELDS:
        if field not in workspace_package:
            errors.append(
                f"workspace.package.{field} is missing (needed for crates.io)"
            )
    errors.extend(
        validate_workspace_rust_version(repo_root, workspace_package)
    )

    for name, path in sorted(manifests.items()):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        package = data.get("package", {})
        if not isinstance(package, dict):
            errors.append(f"{name}: missing [package] table")
            continue
        for field in REGISTRY_INHERIT_FIELDS:
            if not inherits_workspace_field(package, field):
                errors.append(f"{name}: {field}.workspace = true is required")
    return errors


def validate_crate_descriptions(manifests: dict[str, Path]) -> list[str]:
    """Require verilyze in crate descriptions; reject en/em dashes."""
    errors: list[str] = []
    en_dash = "\u2013"
    em_dash = "\u2014"
    for name, path in sorted(manifests.items()):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        package = data.get("package", {})
        description = (
            package.get("description") if isinstance(package, dict) else None
        )
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{name}: missing package.description")
            continue
        if "verilyze" not in description.casefold():
            errors.append(f"{name}: description must mention verilyze")
        if en_dash in description or em_dash in description:
            errors.append(
                f"{name}: description has an en/em dash; use -- or -"
            )
    return errors


def validate_manifest_publish_flags(manifests: dict[str, Path]) -> list[str]:
    """Fail when a production crate still sets publish = false."""
    errors: list[str] = []
    for name, path in sorted(manifests.items()):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        package = data.get("package", {})
        if package.get("publish") is False:
            errors.append(f"{name}: publish = false blocks crates.io")
    return errors


def validate_vlz_assets(repo_root: Path) -> list[str]:
    """Ensure vlz crate assets match repo sources of truth."""
    errors: list[str] = []
    config_src = repo_root / "scripts" / "config-comments.toml"
    config_dst = (
        repo_root
        / "crates"
        / "core"
        / "vlz"
        / "assets"
        / "config-comments.toml"
    )
    man_src = repo_root / "man" / "vlz.1"
    man_dst = repo_root / "crates" / "core" / "vlz" / "assets" / "vlz.1"
    pairs = ((config_src, config_dst), (man_src, man_dst))
    for src, dst in pairs:
        if not dst.is_file():
            errors.append(f"missing vlz asset: {dst.relative_to(repo_root)}")
            continue
        if src.read_text(encoding="utf-8") != dst.read_text(encoding="utf-8"):
            rel = dst.relative_to(repo_root)
            errors.append(
                f"{rel} is out of sync; run make sync-vlz-crate-assets"
            )
    return errors


def default_feature_set(manifest_path: Path) -> set[str]:
    """Return default Cargo features for the crate manifest."""
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    features = data.get("features", {})
    if not isinstance(features, dict):
        return set()
    default = features.get("default", [])
    if isinstance(default, list):
        return {str(item) for item in default}
    return set()


def list_vlz_package_binaries(crate_name: str, repo_root: Path) -> set[str]:
    """Return binary names installed by default (default features only)."""
    if crate_name != "vlz":
        return set()
    manifest = repo_root / "crates" / "core" / "vlz" / "Cargo.toml"
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    default_features = default_feature_set(manifest)
    binaries: set[str] = set()
    for entry in data.get("bin", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        required = entry.get("required-features", [])
        if isinstance(required, list) and required:
            if not all(str(item) in default_features for item in required):
                continue
        binaries.add(name)
    return binaries


def validate_vlz_install_binaries(repo_root: Path) -> list[str]:
    """Ensure only the vlz binary installs by default."""
    binaries = list_vlz_package_binaries("vlz", repo_root)
    extra = sorted(binaries - VLZ_INSTALL_BINARIES)
    if extra:
        return [f"vlz package exposes extra binaries: {', '.join(extra)}"]
    if "vlz" not in binaries:
        return ["vlz package is missing the vlz binary target"]
    return []


def run_cargo_package(
    crate: str, repo_root: Path
) -> subprocess.CompletedProcess[str]:
    """Run cargo package --locked for one workspace crate."""
    cmd = ["cargo", "package", "--locked", "-p", crate]
    if os.environ.get("VLZ_ALLOW_DIRTY_PACKAGE", "1") != "0":
        cmd.append("--allow-dirty")
    return subprocess.run(  # nosec B603
        cmd,
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )


def leaf_crates(manifests: dict[str, Path]) -> list[str]:
    """Return published crates with no internal workspace dependencies."""
    leaves = [
        name
        for name, path in sorted(manifests.items())
        if not parse_internal_dependencies(path)
    ]
    return leaves


def crate_registry_search_query(crate: str, version: str) -> str:
    """Return a cargo search query for an exact crate version."""
    return f"{crate} ={version}"


def is_publish_duplicate_error(output: str) -> bool:
    """Return True when cargo publish failed because the version exists."""
    lowered = output.casefold()
    return (
        "already uploaded" in lowered
        or "already exists on crates.io" in lowered
    )


def run_cargo_registry_search(
    crate: str, version: str, repo_root: Path
) -> subprocess.CompletedProcess[str]:
    """Run cargo search for an exact crate version."""
    return subprocess.run(  # nosec B603 B607
        [
            "cargo",
            "search",
            crate_registry_search_query(crate, version),
            "--limit",
            "1",
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )


def crate_already_on_registry(
    crate: str, version: str, repo_root: Path
) -> bool:
    """Return True when crates.io already lists the given crate version."""
    result = run_cargo_registry_search(crate, version, repo_root)
    if result.returncode != 0:
        return False
    needle = f'= "{version}"'
    return needle in result.stdout


def run_cargo_publish(
    crate: str, repo_root: Path
) -> subprocess.CompletedProcess[str]:
    """Run cargo publish --locked for one workspace crate."""
    return subprocess.run(  # nosec B603 B607
        ["cargo", "publish", "--locked", "-p", crate],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )


def publish_release_crates(
    repo_root: Path,
    *,
    version: str | None = None,
) -> list[str]:
    """Publish workspace crates in order; return fatal error messages."""
    cargo_toml = repo_root / "Cargo.toml"
    workspace_version = version or read_workspace_version(cargo_toml)
    manifests = discover_crate_manifests(repo_root)
    errors: list[str] = []
    for crate in publish_order(manifests):
        if crate_already_on_registry(crate, workspace_version, repo_root):
            print(
                f"cargo-publish-release: skip {crate} {workspace_version} "
                "(already published)"
            )
            continue
        print(f"cargo-publish-release: publishing {crate} {workspace_version}")
        result = run_cargo_publish(crate, repo_root)
        if result.returncode == 0:
            continue
        combined = f"{result.stdout}\n{result.stderr}"
        if is_publish_duplicate_error(combined):
            print(
                f"cargo-publish-release: skip {crate} {workspace_version} "
                "(already published; registry index lag)"
            )
            continue
        errors.append(f"cargo publish -p {crate} failed:\n{combined.strip()}")
    return errors


def check_crates_publish(
    repo_root: Path,
    *,
    package_leaves: bool = True,
) -> list[str]:
    """Run manifest validation and optional leaf-only cargo package checks."""
    errors: list[str] = []
    errors.extend(validate_workspace_dep_versions(repo_root))
    manifests = discover_crate_manifests(repo_root)
    errors.extend(validate_manifest_publish_flags(manifests))
    errors.extend(validate_registry_metadata(repo_root, manifests))
    errors.extend(validate_crate_descriptions(manifests))
    errors.extend(validate_vlz_assets(repo_root))
    errors.extend(validate_vlz_install_binaries(repo_root))
    if errors:
        return errors

    if package_leaves:
        for crate in leaf_crates(manifests):
            result = run_cargo_package(crate, repo_root)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                errors.append(f"cargo package -p {crate} failed:\n{stderr}")
    return errors


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="crates.io publish helpers for the verilyze workspace"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate manifests and run cargo package / publish --dry-run",
    )
    parser.add_argument(
        "--list-order",
        action="store_true",
        help="Print bottom-up crates.io publish order",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="With --check, skip cargo package and publish --dry-run",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish workspace crates to crates.io in dependency order",
    )
    args = parser.parse_args(argv)
    repo_root = get_repo_root()

    if args.publish:
        errors = publish_release_crates(repo_root)
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print("cargo-publish-release: OK")
        return 0

    if args.list_order:
        manifests = discover_crate_manifests(repo_root)
        for name in publish_order(manifests):
            print(name)
        return 0

    if args.check:
        errors = check_crates_publish(
            repo_root,
            package_leaves=not args.manifest_only,
        )
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
