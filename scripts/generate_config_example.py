#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Generate verilyze.conf.example, docs/configuration.md, and man/verilyze.conf.5
from vlz config --list output and config-comments.toml.

Single source of truth: config.rs defines defaults; this script produces
documentation. Run from repository root:
  python scripts/generate_config_example.py

Outputs:
  verilyze.conf.example
  docs/configuration.md
  man/verilyze.conf.5
"""

from __future__ import annotations

import argparse
import os
import subprocess  # nosec B404
import sys
import textwrap
import tomllib
from pathlib import Path


def get_line_length() -> int:
    """Return line-length from pyproject.toml [tool.verilyze]."""
    repo_root = get_repo_root()
    pyproject_path = repo_root / "pyproject.toml"
    if not pyproject_path.exists():
        return 79
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    try:
        return int(data["tool"]["verilyze"]["line-length"])
    except (KeyError, TypeError, ValueError):
        return 79


def wrap_comment(text: str, width: int | None = None) -> list[str]:
    """
    Wrap text into comment lines, each prefixed with '# ' and at most width.
    Returns empty list for empty text.
    """
    if not text.strip():
        return []
    if width is None:
        width = get_line_length()
    prefix = "# "
    content_width = width - len(prefix)
    wrapped = textwrap.wrap(text, width=content_width, break_long_words=True)
    return [prefix + line for line in wrapped]


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def _stringify_toml_value(value: object) -> str:
    """Normalize TOML leaf values to strings for table and man output."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def parse_config_comments(toml_path: Path) -> dict[str, dict[str, str]]:
    """
    Parse config-comments.toml with stdlib tomllib.

    Returns dict of key -> {description, type, env, cli, default?}.
    """
    with toml_path.open("rb") as f:
        data = tomllib.load(f)
    if not isinstance(data, dict):
        return {}

    result: dict[str, dict[str, str]] = {}
    for top_key, nested in data.items():
        key = str(top_key)
        if nested is None or not isinstance(nested, dict):
            result[key] = {}
            continue
        row: dict[str, str] = {}
        for k, v in nested.items():
            sk = str(k)
            raw = _stringify_toml_value(v)
            if sk == "description":
                row[sk] = " ".join(raw.split())
            else:
                row[sk] = raw
        result[key] = row
    return result


def run_config_list(repo_root: Path) -> dict[str, str]:
    """
    Run vlz config --list in clean env, parse key = value output.
    Returns dict of key -> value.
    """
    vlz: Path | str = repo_root / "target" / "debug" / "vlz"
    if isinstance(vlz, Path) and not vlz.exists():
        vlz = repo_root / "target" / "release" / "vlz"
    if isinstance(vlz, Path) and not vlz.exists():
        vlz = "vlz"

    tmp_base = repo_root / ".tmp-empty-xdg"
    tmp_base.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(tmp_base / "config")
    env["XDG_CACHE_HOME"] = str(tmp_base / "cache")
    env["XDG_DATA_HOME"] = str(tmp_base / "data")
    env["HOME"] = str(tmp_base / "home")
    for sub in ("config", "cache", "data", "home"):
        (tmp_base / sub).mkdir(parents=True, exist_ok=True)

    result = subprocess.run(  # nosec B603
        [str(vlz), "config", "--list"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        env=env,
        check=False,
    )
    if result.returncode != 0:
        print(
            "Error: vlz config --list failed:",
            result.stderr,
            file=sys.stderr,
        )
        sys.exit(1)

    parsed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if " = " in line:
            key, _, value = line.partition(" = ")
            parsed[key.strip()] = value.strip()

    return parsed


def _sanitize_config_for_docs(config_list: dict[str, str]) -> dict[str, str]:
    """
    Replace build-artifact paths with empty string for doc-friendly output.
    cache_db and ignore_db may contain .tmp-empty-xdg when vlz runs in
    isolation; docs should show placeholder, not that path.
    """
    result = dict(config_list)
    for key in ("cache_db", "ignore_db"):
        if key in result and ".tmp-empty-xdg" in result.get(key, ""):
            result[key] = ""
    return result


# Fallback when config_list is empty (e.g. tests); order for output.
_FALLBACK_SCALAR_KEYS = [
    "cache_db",
    "ignore_db",
    "parallel_queries",
    "cache_ttl_secs",
    "min_score",
    "min_count",
    "exit_code_on_cve",
    "fp_exit_code",
    "backoff_base_ms",
    "backoff_max_ms",
    "max_retries",
]


def _language_keys_from_config(
    config_list: dict[str, str],
    comments: dict[str, dict[str, str]],
) -> list[tuple[str, str]]:
    """
    Derive (lang, default) pairs from config_list and comments.
    Keys matching *.regex yield the language part.
    """
    langs: dict[str, str] = {}
    for key in config_list:
        if key.endswith(".regex"):
            lang = key[:-6]
            if lang:
                langs[lang] = config_list.get(key, "")
    for key in comments:
        if key.endswith(".regex"):
            lang = key[:-6]
            if lang and lang not in langs:
                langs[lang] = comments.get(key, {}).get("default", "")
    return sorted(langs.items())


def _scalar_keys_from_config_list(
    config_list: dict[str, str],
    comments: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Derive scalar keys from config --list (exclude severity, lang.regex)."""
    keys = [
        k
        for k in config_list.keys()
        if not k.startswith("severity_") and ".regex" not in k
    ]
    if keys:
        return keys
    if comments:
        known = [k for k in _FALLBACK_SCALAR_KEYS if k in comments]
        extra = [
            k
            for k in comments
            if k not in _FALLBACK_SCALAR_KEYS
            and not k.startswith("severity_")
            and ".regex" not in k
        ]
        return known + extra
    return _FALLBACK_SCALAR_KEYS


def build_config_data(
    config_list: dict[str, str],
    comments: dict[str, dict[str, str]],
) -> list[tuple[str, str, str, str, str]]:
    """
    Merge config --list with comments. Returns list of
    (key, default, type, env, cli) for scalar options.
    Keys derived from config_list (single source of truth).
    """
    scalar_keys = _scalar_keys_from_config_list(config_list, comments)

    rows: list[tuple[str, str, str, str, str]] = []
    for key in scalar_keys:
        meta = comments.get(key, {})
        default = config_list.get(key, meta.get("default", ""))
        type_ = meta.get("type", "string")
        env = meta.get("env", "")
        cli = meta.get("cli", "")
        rows.append((key, default, type_, env, cli))

    return rows


def build_severity_data(
    config_list: dict[str, str],
    comments: dict[str, dict[str, str]],
) -> str:
    """Build severity section markdown. Uses config_list when available."""
    versions = ["v2", "v3", "v4"]
    thresholds = ["critical_min", "high_min", "medium_min", "low_min"]

    lines = [
        "| Version | critical_min | high_min | medium_min | low_min |",
        "|---------|--------------|----------|------------|--------|",
    ]
    for v in versions:
        vals = []
        for t in thresholds:
            key = f"severity_{v}_{t}"
            val = config_list.get(key) or comments.get(key, {}).get(
                "default", "-"
            )
            vals.append(val)
        lines.append(f"| {v} | " + " | ".join(vals) + " |")

    return "\n".join(lines)


def generate_example_conf(
    config_list: dict[str, str],
    comments: dict[str, dict[str, str]],
) -> str:
    """Generate verilyze.conf.example content."""
    # REUSE-IgnoreStart -- generated output, not a license declaration
    lines = [
        "# verilyze(1) configuration file",
        "# Copy to ~/.config/verilyze/verilyze.conf or /etc/verilyze.conf",
        "# Precedence: CLI > env (VLZ_*) > user config > system config",
        "#",
    ]

    # Scalar options (keys from config_list, single source of truth)
    scalar_keys = _scalar_keys_from_config_list(config_list, comments)
    for key in scalar_keys:
        default = config_list.get(key) or comments.get(key, {}).get(
            "default", ""
        )
        desc = comments.get(key, {}).get("description", "")
        if key in ("cache_db", "ignore_db") and not default:
            val_line = f'# {key} = "/path/to/db.redb"'
        else:
            path_keys = ("cache_db", "ignore_db")
            val = f'"{default}"' if default and key in path_keys else default
            val_line = f"# {key} = {val}"
        for comment_line in wrap_comment(desc):
            lines.append(comment_line)
        lines.append(val_line)
        lines.append("")

    # Severity (values from config_list when available)
    lines.append("#")
    lines.append(
        "# [severity.v2], [severity.v3], [severity.v4] (CVSS thresholds)"
    )
    for v in ["v2", "v3", "v4"]:
        lines.append(f"# [severity.{v}]")
        for t in ["critical_min", "high_min", "medium_min", "low_min"]:
            key = f"severity_{v}_{t}"
            default = config_list.get(key) or comments.get(key, {}).get(
                "default", ""
            )
            lines.append(f"# {t} = {default}")
        lines.append("#")

    # Language regex
    lines.append("# Per-language manifest regex (FR-006)")
    for lang, default in _language_keys_from_config(config_list, comments):
        if not default:
            default = comments.get(f"{lang}.regex", {}).get("default", "")
        lines.append(f"# [{lang}]")
        lines.append(f'# regex = "{default}"')
        lines.append("")

    # REUSE-IgnoreEnd
    return "\n".join(lines) + "\n"


def generate_config_table(rows: list[tuple[str, str, str, str, str]]) -> str:
    """Generate markdown table rows."""
    lines = []
    for key, default, type_, env, cli in rows:
        cli_display = f"`{cli}`" if cli else "-"
        env_display = f"`{env}`" if env else "-"
        row = (
            f"| {key} | {type_} | {default} | {env_display} | {cli_display} |"
        )
        lines.append(row)
    return "\n".join(lines)


def generate_man_options(
    config_list: dict[str, str],
    comments: dict[str, dict[str, str]],
) -> str:
    """Generate mdoc OPTIONS section."""
    lines = [".Bl -tag -width Ds"]

    scalar_keys = _scalar_keys_from_config_list(config_list, comments)
    for key in scalar_keys:
        meta = comments.get(key, {})
        default = config_list.get(key) or meta.get("default", "")
        desc = meta.get("description", "")
        env = meta.get("env", "")
        cli = meta.get("cli", "")
        lines.append(f".It Va {key}")
        lines.append(f"{desc}.")
        if default:
            lines.append(f"Default: {default}.")
        if env:
            lines.append(f"Env: {env}.")
        if cli:
            lines.append(f"CLI: {cli}.")
        lines.append("")

    lines.append(".It Sy [severity.v2] , Sy [severity.v3] , Sy [severity.v4]")
    lines.append(
        "CVSS score thresholds: critical_min, high_min, medium_min, low_min."
    )
    lines.append("Defaults: 9.0, 7.0, 4.0, 0.1.")
    lines.append("")
    lines.append(".It Sy [lang].regex")
    lines.append(
        "Per-language regex for manifest file names (e.g. [python], [rust], "
        "[go])."
    )
    lines.append(".El")

    return "\n".join(lines)


def _check_outputs_in_sync(
    repo_root: Path,
    example_content: str,
    md_content: str,
    man_content: str,
) -> bool:
    """Return True if all generated files match expected content."""
    paths = [
        (repo_root / "verilyze.conf.example", example_content),
        (repo_root / "docs" / "configuration.md", md_content),
        (repo_root / "man" / "verilyze.conf.5", man_content),
    ]
    for path, expected in paths:
        if not path.exists():
            print(
                f"Error: {path} missing. Run: make generate-config-example",
                file=sys.stderr,
            )
            return False
        if path.read_text(encoding="utf-8") != expected:
            print(
                f"Error: {path} is out of sync. "
                "Run: make generate-config-example",
                file=sys.stderr,
            )
            return False
    return True


def main() -> int:  # pylint: disable=too-many-locals
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Generate config documentation"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify generated files match; exit 1 if out of sync",
    )
    args = parser.parse_args()

    repo_root = get_repo_root()
    manifest_path = repo_root / "scripts" / "config-comments.toml"
    template_md = repo_root / "docs" / "configuration.md.in"
    template_man = repo_root / "man" / "verilyze.conf.5.in"

    for path in (manifest_path, template_md, template_man):
        if not path.exists():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1

    comments = parse_config_comments(manifest_path)
    config_list = run_config_list(repo_root)
    config_list = _sanitize_config_for_docs(config_list)
    rows = build_config_data(config_list, comments)

    example_content = generate_example_conf(config_list, comments)
    config_table = generate_config_table(rows)
    severity_section = build_severity_data(config_list, comments)
    md_content = template_md.read_text(encoding="utf-8")
    md_content = md_content.replace("{{CONFIG_TABLE}}", config_table)
    md_content = md_content.replace("{{SEVERITY_SECTION}}", severity_section)
    options_section = generate_man_options(config_list, comments)
    man_content = template_man.read_text(encoding="utf-8")
    man_content = man_content.replace("{{OPTIONS_SECTION}}", options_section)

    if args.check:
        return (
            0
            if _check_outputs_in_sync(
                repo_root, example_content, md_content, man_content
            )
            else 1
        )

    (repo_root / "verilyze.conf.example").write_text(
        example_content, encoding="utf-8"
    )
    (repo_root / "docs" / "configuration.md").write_text(
        md_content, encoding="utf-8"
    )
    (repo_root / "man" / "verilyze.conf.5").write_text(
        man_content, encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
