#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Add REUSE-compliant copyright and license headers to covered text files.

Uses git history and the 15-line "nontrivial change" threshold
(see docs/NONTRIVIAL-CHANGE.md).

Run from repository root: python scripts/update_headers.py [--print-config]
"""

import argparse
import fnmatch
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
_GIT_LOG_FALLBACK_MAX_COMMITS: int = 50
_DEFAULT_BOT_EMAIL_MARKERS: tuple[str, ...] = ("[bot]",)


class HeadersConfig(TypedDict):
    """Config from [tool.vlz-headers] in pyproject.toml."""

    default_copyright: str
    default_license: str
    nontrivial_lines: int
    extensions: tuple[str, ...]
    literal_names: tuple[str, ...]
    exclude_paths: tuple[str, ...]
    bot_email_markers: tuple[str, ...]


# Defaults when pyproject.toml keys are missing
_DEFAULTS: HeadersConfig = {
    "default_copyright": "The verilyze contributors",
    "default_license": "GPL-3.0-or-later",
    "nontrivial_lines": 15,
    "extensions": (
        "py",
        "rs",
        "toml",
        "md",
        "mmd",
        "sh",
        "json",
        "yml",
        "yaml",
    ),
    "literal_names": ("Makefile",),
    "exclude_paths": ("tools/xtask", "Cargo.lock"),
    "bot_email_markers": _DEFAULT_BOT_EMAIL_MARKERS,
}


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def _normalize_reuse_path(path: str) -> str:
    """Use forward slashes; drop redundant slashes (git ls-files style)."""
    return "/".join(p for p in path.replace("\\", "/").split("/") if p != "")


def _segment_match(path_segment: str, pattern_segment: str) -> bool:
    """Match one path segment; * is a single-segment wildcard."""
    if pattern_segment == "*":
        return True
    return fnmatch.fnmatchcase(path_segment, pattern_segment)


def _match_path_parts(path_parts: list[str], pat_parts: list[str]) -> bool:
    """
    Match split path against REUSE-style glob segments (** spans directories).
    """

    # pylint: disable=too-many-return-statements
    def rec(pi: int, pj: int) -> bool:
        if pj == len(pat_parts):
            return pi == len(path_parts)
        pat = pat_parts[pj]
        if pat == "**":
            if pj == len(pat_parts) - 1:
                return True
            for k in range(pi, len(path_parts) + 1):
                if rec(k, pj + 1):
                    return True
            return False
        if pi >= len(path_parts):
            return False
        if not _segment_match(path_parts[pi], pat):
            return False
        return rec(pi + 1, pj + 1)

    return rec(0, 0)


def _path_matches_reuse_glob(relative_path: str, pattern: str) -> bool:
    """
    Return True if relative_path matches a REUSE.toml [[annotations]] path.

    Semantics follow common **/* glob usage (segment-wise *; ** spans /).
    """
    rel = _normalize_reuse_path(relative_path)
    pat = _normalize_reuse_path(pattern)
    if not pat:
        return rel == ""
    path_parts = rel.split("/") if rel else []
    pat_parts = pat.split("/")
    return _match_path_parts(path_parts, pat_parts)


def load_reuse_annotation_globs(repo_root: Path) -> tuple[str, ...]:
    """Load path globs from REUSE.toml [[annotations]] entries."""
    path = repo_root / "REUSE.toml"
    if not path.exists():
        return ()
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, ValueError):
        return ()
    anns = data.get("annotations")
    if not isinstance(anns, list):
        return ()
    globs: list[str] = []
    for item in anns:
        if not isinstance(item, dict):
            continue
        p = item.get("path")
        if isinstance(p, str) and p:
            globs.append(p)
    return tuple(globs)


def load_config(repo_root: Path) -> HeadersConfig:
    """
    Load [tool.vlz-headers] from pyproject.toml. Returns dict with keys:
    default_copyright, default_license, nontrivial_lines, extensions,
    literal_names, exclude_paths, bot_email_markers. Uses _DEFAULTS for
    missing keys.
    """
    cfg: HeadersConfig = {
        "default_copyright": _DEFAULTS["default_copyright"],
        "default_license": _DEFAULTS["default_license"],
        "nontrivial_lines": _DEFAULTS["nontrivial_lines"],
        "extensions": _DEFAULTS["extensions"],
        "literal_names": _DEFAULTS["literal_names"],
        "exclude_paths": _DEFAULTS["exclude_paths"],
        "bot_email_markers": _DEFAULTS["bot_email_markers"],
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
        if "bot_email_markers" in section and isinstance(
            section["bot_email_markers"], list
        ):
            raw_markers = [
                str(x) for x in section["bot_email_markers"] if str(x)
            ]
            cfg["bot_email_markers"] = tuple(raw_markers)
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
    reuse_globs = load_reuse_annotation_globs(repo_root)
    paths = [p for p in result.stdout.strip("\0").split("\0") if p]
    covered: list[str] = []
    for path in paths:
        excluded = any(
            path == ex or path.startswith(ex + "/") for ex in exclude_paths
        )
        if excluded:
            continue
        if any(_path_matches_reuse_glob(path, g) for g in reuse_globs):
            continue
        if path == "Cargo.lock":
            continue
        if any(path.endswith("." + ext) for ext in extensions):
            covered.append(path)
            continue
        if Path(path).name in literal_names:
            covered.append(path)
    return covered


def email_matches_bot_markers(email: str, markers: tuple[str, ...]) -> bool:
    """True if email contains a marker substring (case-insensitive)."""
    if not email or not markers:
        return False
    elower = email.lower()
    return any(m.lower() in elower for m in markers if m)


def _extract_email_from_identifier(ident: str) -> str:
    """Return email from 'Name <email>' or '' if not parseable."""
    start = ident.rfind("<")
    end = ident.rfind(">")
    if 0 <= start < end:
        return ident[start + 1 : end].strip()
    return ""


def _is_bot_spdx_holder(entry: str, markers: tuple[str, ...]) -> bool:
    """True if SPDX-style entry's author email matches a bot marker."""
    ident = _extract_identifier(entry)
    return email_matches_bot_markers(
        _extract_email_from_identifier(ident),
        markers,
    )


def _filter_non_bot_copyright_entries(
    entries: list[str],
    markers: tuple[str, ...],
) -> list[str]:
    """Drop copyright lines whose email matches bot markers."""
    return [e for e in entries if not _is_bot_spdx_holder(e, markers)]


def _first_non_bot_git_author(
    repo_root: Path,
    file_path: str,
    config: HeadersConfig,
    *,
    reverse: bool,
) -> str | None:
    """
    Walk up to _GIT_LOG_FALLBACK_MAX_COMMITS commits; return first line
    'YEAR Name <email>' that is not a bot, or None.
    """
    markers = config["bot_email_markers"]
    cmd: list[str] = [
        "git",
        "log",
        "--use-mailmap",
    ]
    if reverse:
        cmd.append("--reverse")
    cmd.extend(
        [
            f"--max-count={_GIT_LOG_FALLBACK_MAX_COMMITS}",
            "--format=%ad %aN <%aE>",
            "--date=format:%Y",
            "--follow",
            "--",
            file_path,
        ]
    )
    result = run(cmd, cwd=repo_root)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if candidate and not _is_bot_spdx_holder(candidate, markers):
            return candidate
    return None


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
                    cached = [ln.strip() for ln in lines if ln.strip()]
                    return _filter_non_bot_copyright_entries(
                        cached,
                        config["bot_email_markers"],
                    )
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
        config["bot_email_markers"],
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


def _parse_git_log_numstat(
    log_output: str,
    threshold: int,
    markers: tuple[str, ...],
) -> list[str]:
    """
    Parse git log --numstat output into "YEAR Author <email>" lines.

    Same logic as the original awk script; then drop bot markers (emails).
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
    return _filter_non_bot_copyright_entries(out, markers)


def resolve_authors(
    repo_root: Path,
    file_path: str,
    raw_authors: list[str],
    config: HeadersConfig,
) -> list[str]:
    """
    Resolve effective authors when get_nontrivial_authors returns empty
    or only bot identities.

    Fallbacks: oldest human author in recent history, then newest human
    author, then default copyright.
    """
    filtered = _filter_non_bot_copyright_entries(
        raw_authors,
        config["bot_email_markers"],
    )
    if filtered:
        return filtered

    first_human = _first_non_bot_git_author(
        repo_root, file_path, config, reverse=True
    )
    if first_human:
        return [first_human]

    recent_human = _first_non_bot_git_author(
        repo_root, file_path, config, reverse=False
    )
    if recent_human:
        return [recent_human]

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


def _build_arg_parser() -> argparse.ArgumentParser:
    """CLI for direct runs and for tooling (pre-commit, Make)."""
    parser = argparse.ArgumentParser(
        prog="update_headers.py",
        description=(
            "Add or refresh REUSE SPDX headers on covered files using git "
            "history (see docs/NONTRIVIAL-CHANGE.md)."
        ),
        exit_on_error=False,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--print-config",
        action="store_true",
        help=(
            "Print license, default copyright, and path patterns as key:value "
            "lines for shells; then exit."
        ),
    )
    mode.add_argument(
        "--is-bot-email",
        dest="bot_email",
        metavar="EMAIL",
        help=(
            "Exit 0 if EMAIL matches configured bot_email_markers, else 1. "
            "Used by scripts/pre-commit-headers.sh."
        ),
    )
    return parser


def _run_full_header_pass(repo_root: Path) -> int:
    """Default mode: ensure REUSE deps and annotate all covered files."""
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


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point.

    argv: if None, uses sys.argv[1:] (script name is never included).
    """
    repo_root = get_repo_root()
    parser = _build_arg_parser()
    try:
        args = parser.parse_args(argv)
    except argparse.ArgumentError as err:
        print(str(err), file=sys.stderr)
        return 2

    if args.print_config:
        config = load_config(repo_root)
        _print_config(config)
        return 0

    if args.bot_email is not None:
        config = load_config(repo_root)
        if email_matches_bot_markers(
            args.bot_email,
            config["bot_email_markers"],
        ):
            return 0
        return 1

    return _run_full_header_pass(repo_root)


if __name__ == "__main__":
    sys.exit(main())
