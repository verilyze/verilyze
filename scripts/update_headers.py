#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Add REUSE-compliant copyright and license headers to covered text files.

Uses git history and the 15-line "nontrivial change" threshold
(see docs/NONTRIVIAL-CHANGE.md).

Run from repository root: python scripts/update_headers.py
"""

import hashlib
import os
import re
import subprocess  # nosec B404
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

# Internal defaults (not in pyproject.toml)
_CONFIG_MAX_WORKERS: int = 8
_CONFIG_CACHE_DIR: str = ".cache/update-headers"


class HeadersConfig(TypedDict):
    """Config from [tool.vlz-headers] in pyproject.toml."""

    default_copyright: str
    default_license: str
    nontrivial_lines: int
    extensions: tuple[str, ...]
    literal_names: tuple[str, ...]
    exclude_paths: tuple[str, ...]


# Defaults when pyproject.toml keys are missing
_DEFAULTS: HeadersConfig = {
    "default_copyright": "The verilyze contributors",
    "default_license": "GPL-3.0-or-later",
    "nontrivial_lines": 15,
    "extensions": ("py", "rs", "toml", "md", "mmd", "sh", "json"),
    "literal_names": ("Makefile",),
    "exclude_paths": ("tools/xtask", "Cargo.lock"),
}


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def load_config(repo_root: Path) -> HeadersConfig:
    """
    Load [tool.vlz-headers] from pyproject.toml. Returns dict with keys:
    default_copyright, default_license, nontrivial_lines, extensions,
    literal_names, exclude_paths. Uses _DEFAULTS for missing keys.
    """
    cfg: HeadersConfig = {
        "default_copyright": _DEFAULTS["default_copyright"],
        "default_license": _DEFAULTS["default_license"],
        "nontrivial_lines": _DEFAULTS["nontrivial_lines"],
        "extensions": _DEFAULTS["extensions"],
        "literal_names": _DEFAULTS["literal_names"],
        "exclude_paths": _DEFAULTS["exclude_paths"],
    }
    path = repo_root / "pyproject.toml"
    if not path.exists():
        return cfg
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
        tool = data.get("tool") or {}
        section: dict[str, Any] = dict(tool.get("vlz-headers") or {})
        if "default_copyright" in section and isinstance(
            section["default_copyright"], str
        ):
            cfg["default_copyright"] = section["default_copyright"]
        if "default_license" in section and isinstance(
            section["default_license"], str
        ):
            cfg["default_license"] = section["default_license"]
        if "nontrivial_lines" in section and isinstance(
            section["nontrivial_lines"], int
        ):
            cfg["nontrivial_lines"] = section["nontrivial_lines"]
        for key in ("extensions", "literal_names", "exclude_paths"):
            if key in section and isinstance(section[key], list):
                cfg[key] = tuple(str(x) for x in section[key])
    except (OSError, ValueError):
        pass
    return cfg


def get_reuse_cmd(repo_root: Path) -> Path:
    """Return path to ensure-reuse.sh."""
    return repo_root / "scripts" / "ensure-reuse.sh"


def run(
    cmd: list[str],
    cwd: Path | None = None,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run command, return CompletedProcess. Suppresses stderr on failure."""
    return subprocess.run(  # nosec B603
        cmd,
        cwd=cwd,
        capture_output=capture,
        text=True,
        check=False,
    )


def collect_files(repo_root: Path, config: HeadersConfig) -> list[str]:
    """Return covered files (git-tracked, matching patterns, not excluded)."""
    result = run(["git", "ls-files", "-z"], cwd=repo_root)
    if result.returncode != 0:
        return []
    exclude_paths = config["exclude_paths"]
    extensions = config["extensions"]
    literal_names = config["literal_names"]
    paths = [p for p in result.stdout.strip("\0").split("\0") if p]
    covered: list[str] = []
    for path in paths:
        excluded = any(
            path == ex or path.startswith(ex + "/") for ex in exclude_paths
        )
        if excluded:
            continue
        if path == "Cargo.lock":
            continue
        if any(path.endswith("." + ext) for ext in extensions):
            covered.append(path)
            continue
        if Path(path).name in literal_names:
            covered.append(path)
    return covered


def get_nontrivial_authors(
    repo_root: Path,
    file_path: str,
    cache_dir: Path | None,
    config: HeadersConfig,
) -> list[str]:
    """
    Return "YEAR Author <email>" for contributors with >= nontrivial_lines.

    Uses cache when cache_dir is set (key: HEAD:file_path).
    """
    head = ""
    if cache_dir:
        try:
            rev_parse = run(["git", "rev-parse", "HEAD"], cwd=repo_root)
            if rev_parse.returncode == 0:
                head = rev_parse.stdout.strip()
                key = f"{head}:{file_path}"
                digest = hashlib.sha256(key.encode()).hexdigest()
                cache_file = cache_dir / digest
                if cache_file.exists():
                    lines = cache_file.read_text().strip().splitlines()
                    return [ln.strip() for ln in lines if ln.strip()]
        except OSError:
            pass

    result = run(
        [
            "git",
            "log",
            "--use-mailmap",
            "--numstat",
            "--format=%aN <%aE>%n%ad",
            "--date=format:%Y",
            "--follow",
            "--",
            file_path,
        ],
        cwd=repo_root,
    )
    if result.returncode != 0:
        return []

    authors = _parse_git_log_numstat(
        result.stdout,
        config["nontrivial_lines"],
    )
    if cache_dir and head:
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            key = f"{head}:{file_path}"
            digest = hashlib.sha256(key.encode()).hexdigest()
            cache_file = cache_dir / digest
            cache_file.write_text("\n".join(authors) + "\n")
        except OSError:
            pass
    return authors


def _parse_git_log_numstat(log_output: str, threshold: int) -> list[str]:
    """
    Parse git log --numstat output into "YEAR Author <email>" lines.

    Same logic as the original awk script.
    """
    # pylint: disable=too-many-locals
    add: dict[str, int] = {}
    firstyear: dict[str, str] = {}
    lastyear: dict[str, str] = {}
    author = ""
    year = ""
    for line in log_output.splitlines():
        # Numstat line: add\tdel\tpath
        if re.match(r"^\d+\t", line):
            if author:
                parts = line.split("\t")
                inc = int(parts[0]) if parts[0].isdigit() else 0
                add[author] = add.get(author, 0) + inc
                if year:
                    if author not in firstyear:
                        firstyear[author] = year
                    lastyear[author] = year
            continue
        # Year line
        if re.match(r"^\d{4}$", line):
            year = line
            continue
        # Author line
        if line and not re.match(r"^\d", line):
            author = line
            year = ""
            continue

    out: list[str] = []
    for author_key, count in add.items():
        if count >= threshold and author_key:
            fy = firstyear.get(author_key) or "?"
            ly = lastyear.get(author_key) or "?"
            yrange = fy if fy == ly else f"{fy}-{ly}"
            out.append(f"{yrange} {author_key}")
    return out


def resolve_authors(
    repo_root: Path,
    file_path: str,
    raw_authors: list[str],
    config: HeadersConfig,
) -> list[str]:
    """
    Resolve effective authors when get_nontrivial_authors returns empty.

    Fallbacks: first commit author, then most recent author,
    then default copyright.
    """
    if raw_authors:
        return raw_authors
    result = run(
        [
            "git",
            "log",
            "--use-mailmap",
            "--reverse",
            "-1",
            "--format=%ad %aN <%aE>",
            "--date=format:%Y",
            "--follow",
            "--",
            file_path,
        ],
        cwd=repo_root,
    )
    if result.returncode == 0 and result.stdout.strip():
        return [result.stdout.strip()]
    result = run(
        [
            "git",
            "log",
            "--use-mailmap",
            "-1",
            "--format=%ad %aN <%aE>",
            "--date=format:%Y",
            "--",
            file_path,
        ],
        cwd=repo_root,
    )
    if result.returncode == 0 and result.stdout.strip():
        return [result.stdout.strip()]
    year = datetime.now().year
    return [f"{year} {config['default_copyright']}"]


def _extract_identifier(entry: str) -> str:
    """Extract 'Name <email>' from 'YEAR Name <email>' or 'YEAR-YEAR ...'."""
    parts = entry.split(None, 1)
    return parts[1] if len(parts) >= 2 else ""


def _extract_file_identifiers(header: str) -> set[str]:
    """Extract contributor identifiers from SPDX-FileCopyrightText lines."""
    ids: set[str] = set()
    for line in header.splitlines():
        if "SPDX-FileCopyrightText" not in line:
            continue
        match = re.search(r"SPDX-FileCopyrightText:\s*(.+)", line)
        if match:
            content = match.group(1).strip()
            ident = _extract_identifier(content)
            if ident:
                ids.add(ident)
    return ids


def headers_match(
    repo_root: Path,
    file_path: str,
    expected_authors: list[str],
    config: HeadersConfig,
) -> bool:
    """
    Return True if file headers contain all expected authors and license.

    For force-dot-license files (e.g. .mmd), checks file.license.
    """
    full_path = repo_root / file_path
    if not full_path.exists():
        return False
    header_file: Path = full_path
    license_file = Path(str(full_path) + ".license")
    if license_file.exists():
        header_file = license_file
    try:
        header = header_file.read_text(
            encoding="utf-8",
            errors="replace",
        )[:2000]
    except OSError:
        return False
    if "SPDX-FileCopyrightText" not in header:
        return False
    default_license = str(config["default_license"])
    has_license = (
        "SPDX-License-Identifier" in header and default_license in header
    )
    if not has_license:
        return False
    expected_ids: set[str] = set()
    for auth in expected_authors:
        ident = _extract_identifier(auth)
        if ident:
            expected_ids.add(ident)
    file_ids = _extract_file_identifiers(header)
    return expected_ids <= file_ids


def annotate_file(
    repo_root: Path,
    file_path: str,
    authors: list[str],
    config: HeadersConfig,
) -> bool:
    """Annotate file with reuse CLI. Returns True on success."""
    reuse_cmd = get_reuse_cmd(repo_root)
    args = [
        str(reuse_cmd),
        "annotate",
        "-l",
        config["default_license"],
        "--merge-copyrights",
    ]
    for entry in authors:
        ident = _extract_identifier(entry)
        if not ident:
            continue
        # entry is "YEAR Name <email>" or "YEAR-YEAR Name <email>"
        parts = entry.split(None, 1)
        year = parts[0] if parts else ""
        if year:
            args.extend(["-c", ident, "-y", year])
    full_path = repo_root / file_path
    result = run(args + [str(full_path)])
    if result.returncode == 0:
        return True
    result = run(args + ["--force-dot-license", str(full_path)])
    if result.returncode != 0 and (result.stderr or result.stdout):
        print(
            f"Warning: reuse annotate failed for {file_path}:", file=sys.stderr
        )
        if result.stderr:
            print(result.stderr, file=sys.stderr)
    return result.returncode == 0


def process_one_file(
    repo_root: Path,
    file_path: str,
    cache_dir: Path | None,
    config: HeadersConfig,
) -> str | None:
    """
    Process one file: get authors, skip if headers match, else annotate.

    Returns "Annotated: path" if updated, None otherwise.
    """
    full_path = repo_root / file_path
    if not full_path.exists():
        return None
    raw_authors = get_nontrivial_authors(
        repo_root, file_path, cache_dir, config
    )
    effective_authors = resolve_authors(
        repo_root,
        file_path,
        raw_authors,
        config,
    )
    if headers_match(repo_root, file_path, effective_authors, config):
        return None
    if annotate_file(repo_root, file_path, effective_authors, config):
        return f"Annotated: {file_path}"
    return None


def _print_config(config: HeadersConfig) -> None:
    """Output key:value lines for shell parsing (no eval)."""
    ext_str = " ".join(config["extensions"])
    lit_str = " ".join(config["literal_names"])
    excl_str = " ".join(config["exclude_paths"])
    print(f"license:{config['default_license']}")
    print(f"copyright:{config['default_copyright']}")
    print(f"extensions:{ext_str}")
    print(f"literal_names:{lit_str}")
    print(f"exclude_paths:{excl_str}")


def main() -> int:
    """Main entry point."""
    repo_root = get_repo_root()
    if len(sys.argv) == 2 and sys.argv[1] == "--print-config":
        config = load_config(repo_root)
        _print_config(config)
        return 0

    os.chdir(repo_root)
    config = load_config(repo_root)

    reuse_cmd = get_reuse_cmd(repo_root)
    if not reuse_cmd.exists():
        print("ERROR: ensure-reuse.sh not found.", file=sys.stderr)
        return 1

    licenses_dir = repo_root / "LICENSES"
    if not licenses_dir.exists():
        default_license = str(config["default_license"])
        print(f"Downloading {default_license}...")
        run(
            [str(reuse_cmd), "download", default_license],
            capture=False,
        )

    cache_dir = repo_root / _CONFIG_CACHE_DIR
    files = collect_files(repo_root, config)
    updated = 0

    with ThreadPoolExecutor(max_workers=_CONFIG_MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_one_file,
                repo_root,
                fp,
                cache_dir,
                config,
            ): fp
            for fp in files
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)
                updated += 1

    print(f"Updated {updated} file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
