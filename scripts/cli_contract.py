# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Subprocess CLI contract runner for installed or locally built vlz."""

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UNQUALIFIED_NO_VULNS = "No vulnerabilities found."
REGISTRY_REL = Path("tests/cli_contract/registry.json")
FIXTURES_REL = Path("tests/cli_contract/fixtures")
VLZ_CARGO_REL = Path("crates/core/vlz/Cargo.toml")
CACHE_FEATURE_NAMES = frozenset({"redb", "mem"})
LOCKLESS_PM_ON_PATH = frozenset({"rust", "go"})
# Empty inventory is a successful Transitive scan (FR-038), not exit 4.
EMPTY_INVENTORY_OK = frozenset({"sbom"})
DEFAULT_LANGUAGES = (
    "python",
    "rust",
    "go",
    "javascript",
    "java",
    "ruby",
    "sbom",
)
VALID_MODES = ("smoke", "full")


@dataclass
class CaseResult:
    """Outcome of one registry case."""

    case_id: str
    category: str
    ok: bool
    exit_code: int | None
    detail: str

    def summary(self) -> str:
        """Format a one-line result for logs."""
        status = "ok" if self.ok else "FAIL"
        return (
            f"[{self.category}] {self.case_id}: {status} "
            f"(exit={self.exit_code}) {self.detail}"
        ).rstrip()


def repo_root_from(start: Path | None = None) -> Path:
    """Return the repository root (override or inferred from this file)."""
    if start is not None:
        return start
    return Path(__file__).resolve().parent.parent


def load_registry(root: Path) -> dict[str, Any]:
    """Load tests/cli_contract/registry.json."""
    path = root / REGISTRY_REL
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _feature_language_names(names: Any) -> tuple[str, ...]:
    if not isinstance(names, list):
        raise ValueError("features.runtime must be a list")
    return tuple(
        str(name) for name in names if str(name) not in CACHE_FEATURE_NAMES
    )


def runtime_language_features_from_toml(text: str) -> tuple[str, ...]:
    """Language feature names from vlz ``runtime`` (exclude cache backends)."""
    data = tomllib.loads(text)
    return _feature_language_names(data.get("features", {}).get("runtime"))


def runtime_mem_language_features_from_toml(text: str) -> tuple[str, ...]:
    """Language feature names from vlz ``runtime-mem``."""
    data = tomllib.loads(text)
    names = data.get("features", {}).get("runtime-mem")
    if not isinstance(names, list):
        raise ValueError("features.runtime-mem must be a list")
    return tuple(
        str(name) for name in names if str(name) not in CACHE_FEATURE_NAMES
    )


def load_runtime_language_features(root: Path) -> tuple[str, ...]:
    """Read language features from crates/core/vlz/Cargo.toml ``runtime``."""
    path = root / VLZ_CARGO_REL
    return runtime_language_features_from_toml(
        path.read_text(encoding="utf-8")
    )


def load_runtime_mem_language_features(root: Path) -> tuple[str, ...]:
    """Read ``runtime-mem`` language features from vlz Cargo.toml."""
    path = root / VLZ_CARGO_REL
    return runtime_mem_language_features_from_toml(
        path.read_text(encoding="utf-8")
    )


def _expect_cache_miss(case: dict[str, Any], label: str) -> str | None:
    exits = case.get("expect_exit") or []
    if 0 in exits or 4 in exits or 6 not in exits or 86 not in exits:
        return f"{case.get('id')}: {label}"
    return None


def _lock_offline_errors(cases: list[Any], lang: str) -> list[str]:
    matched = [
        case
        for case in cases
        if isinstance(case, dict)
        and case.get("language") == lang
        and case.get("category") == "lock_parse"
        and "--offline" in (case.get("args") or [])
        and "smoke" in (case.get("modes") or [])
        and "--format" not in (case.get("args") or [])
    ]
    if not matched:
        return [f"{lang}: missing smoke lock_parse --offline without --format"]
    errors: list[str] = []
    for case in matched:
        msg = _expect_cache_miss(case, "lock-offline expect [6, 86]")
        if msg:
            errors.append(msg)
    return errors


def _lockless_policy_errors(cases: list[Any], lang: str) -> list[str]:
    if lang in LOCKLESS_PM_ON_PATH:
        matched = [
            case
            for case in cases
            if isinstance(case, dict)
            and case.get("language") == lang
            and str(case.get("id", "")).endswith("-lockless-offline")
            and "--offline" in (case.get("args") or [])
            and "smoke" in (case.get("modes") or [])
        ]
        if not matched:
            return [
                f"{lang}: missing smoke lock-less --offline "
                "(cargo/go on PATH)"
            ]
        errors: list[str] = []
        for case in matched:
            msg = _expect_cache_miss(case, "lock-less-offline expect 6/86")
            if msg:
                errors.append(msg)
        return errors
    matched = [
        case
        for case in cases
        if isinstance(case, dict)
        and case.get("language") == lang
        and str(case.get("id", "")).endswith("-lockless")
        and "--offline" not in (case.get("args") or [])
    ]
    if not matched:
        return [f"{lang}: missing default lock-less expect 4"]
    errors = []
    for case in matched:
        if case.get("expect_exit") != [4]:
            errors.append(f"{case.get('id')}: default lock-less expect [4]")
    return errors


def _pin_errors(cases: list[Any], lang: str) -> list[str]:
    matched = [
        case
        for case in cases
        if isinstance(case, dict)
        and case.get("language") == lang
        and str(case.get("id", "")).endswith("-lock-offline-pin")
        and "full" in (case.get("modes") or [])
        and "cyclonedx" in (case.get("args") or [])
    ]
    if not matched:
        return [f"{lang}: missing full CycloneDX lock-offline-pin"]
    errors: list[str] = []
    for case in matched:
        msg = _expect_cache_miss(case, "lock-offline-pin expect [6, 86]")
        if msg:
            errors.append(msg)
        needles = case.get("stdout_contains") or []
        if not needles:
            errors.append(f"{case.get('id')}: pin case needs stdout_contains")
    return errors


def _empty_lock_errors(cases: list[Any], lang: str) -> list[str]:
    if lang in LOCKLESS_PM_ON_PATH:
        return []
    matched = [
        case
        for case in cases
        if isinstance(case, dict)
        and case.get("language") == lang
        and "empty" in str(case.get("id", ""))
        and "--offline" not in (case.get("args") or [])
    ]
    if not matched:
        return [f"{lang}: missing default empty-lock case"]
    errors: list[str] = []
    expected = [0] if lang in EMPTY_INVENTORY_OK else [4]
    for case in matched:
        if case.get("expect_exit") != expected:
            errors.append(f"{case.get('id')}: empty-lock expect {expected}")
    return errors


def registry_covers_runtime_languages(
    registry: dict[str, Any],
    langs: tuple[str, ...],
    mem_langs: tuple[str, ...] | None = None,
) -> list[str]:
    """Return errors when a runtime language lacks required CLI cases."""
    errors: list[str] = []
    if mem_langs is not None and set(langs) != set(mem_langs):
        errors.append(
            "runtime and runtime-mem language features differ: "
            f"{tuple(langs)} vs {tuple(mem_langs)}"
        )
    cases = registry.get("cases")
    if not isinstance(cases, list):
        errors.append("registry cases must be a list")
        return errors
    for lang in langs:
        errors.extend(_lock_offline_errors(cases, lang))
        errors.extend(_lockless_policy_errors(cases, lang))
        errors.extend(_pin_errors(cases, lang))
        errors.extend(_empty_lock_errors(cases, lang))
    return errors


def cases_for_mode(
    registry: dict[str, Any], mode: str
) -> list[dict[str, Any]]:
    """Select cases whose modes list includes *mode*."""
    if mode not in VALID_MODES:
        raise ValueError(f"unknown mode: {mode}")
    cases = registry.get("cases")
    if not isinstance(cases, list):
        raise ValueError("registry cases must be a list")
    selected: list[dict[str, Any]] = []
    for case in cases:
        modes = case.get("modes") or ["smoke", "full"]
        if mode in modes:
            selected.append(case)
    return selected


def validate_registry(root: Path, registry: dict[str, Any]) -> list[str]:
    """Return human-readable errors for missing fixtures or args."""
    errors: list[str] = []
    fixtures_root = root / FIXTURES_REL
    for case in registry.get("cases", []):
        fixture = case.get("fixture")
        if fixture:
            path = fixtures_root / str(fixture)
            if not path.is_dir():
                errors.append(f"{case.get('id')}: missing fixture {path}")
        args = case.get("args")
        if not isinstance(args, list) or not args:
            errors.append(f"{case.get('id')}: args must be a non-empty list")
    return errors


def substitute_args(args: list[str], fixture: Path | None) -> list[str]:
    """Replace {fixture} placeholders with the fixture directory."""
    out: list[str] = []
    for arg in args:
        if "{fixture}" in arg:
            if fixture is None:
                raise ValueError("fixture placeholder without fixture path")
            out.append(arg.replace("{fixture}", str(fixture)))
        else:
            out.append(arg)
    return out


FIXTURE_SUFFIX = ".fixture"


def materialize_fixture_tree(src: Path, dest: Path) -> None:
    """Copy a fixture dir, stripping ``.fixture`` for real basenames."""
    dest.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.is_dir():
            materialize_fixture_tree(item, dest / item.name)
            continue
        if not item.is_file():
            continue
        name = item.name
        if name.endswith(".license"):
            continue
        if name.endswith(FIXTURE_SUFFIX):
            name = name[: -len(FIXTURE_SUFFIX)]
        shutil.copy2(item, dest / name)


def isolated_env(binary: Path, xdg_root: Path) -> dict[str, str]:
    """Copy vlz onto a PATH that contains only that binary."""
    xdg_root.mkdir(parents=True, exist_ok=True)
    bin_dir = xdg_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dest = bin_dir / binary.name
    if dest.exists():
        dest.unlink()
    shutil.copy2(binary, dest)
    dest.chmod(dest.stat().st_mode | 0o111)
    env = os.environ.copy()
    env["PATH"] = str(bin_dir)
    env["XDG_CACHE_HOME"] = str(xdg_root)
    env["XDG_DATA_HOME"] = str(xdg_root)
    env["XDG_CONFIG_HOME"] = str(xdg_root)
    env["VLZ_IGNORE_DB"] = str(xdg_root / "vlz-ignore.json")
    env.pop("VLZ_CACHE_DB", None)
    env["RUST_LOG"] = "off"
    env["RUST_LOG_STYLE"] = "never"
    return env


def _contains(haystack: str, needle: str) -> bool:
    return needle in haystack


def _match_needles(
    stdout: str,
    stderr: str,
    case: dict[str, Any],
    ok: bool,
    detail_parts: list[str],
) -> bool:
    combined = stdout + stderr
    for needle in case.get("stdout_contains") or []:
        if not _contains(stdout, str(needle)):
            ok = False
            detail_parts.append(f"stdout missing {needle!r}")
    for needle in case.get("stderr_contains") or []:
        if not _contains(stderr, str(needle)):
            ok = False
            detail_parts.append(f"stderr missing {needle!r}")
    for needle in case.get("stdout_forbids") or []:
        if _contains(stdout, str(needle)):
            ok = False
            detail_parts.append(f"stdout contains forbidden {needle!r}")
    for needle in case.get("combined_contains") or []:
        if not _contains(combined, str(needle)):
            ok = False
            detail_parts.append(f"output missing {needle!r}")
    return ok


def run_argv(binary: Path, case: dict[str, Any], xdg_root: Path) -> CaseResult:
    """Run one argv case with an isolated environment."""
    category = str(case.get("category") or "cli_contract")
    case_id = str(case.get("id") or "unknown")
    args = list(case["args"])
    try:
        env = isolated_env(binary, xdg_root)
        proc = subprocess.run(  # nosec B603
            [str(binary), *args],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except OSError as exc:
        return CaseResult(case_id, category, False, None, str(exc))
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    expect_exit = case.get("expect_exit") or [0]
    ok = proc.returncode in expect_exit
    detail_parts: list[str] = []
    if not ok:
        detail_parts.append(
            f"expected exit {expect_exit}, got {proc.returncode}"
        )
    ok = _match_needles(stdout, stderr, case, ok, detail_parts)
    return CaseResult(
        case_id,
        category,
        ok,
        proc.returncode,
        "; ".join(detail_parts),
    )


def run_case(root: Path, binary: Path, case: dict[str, Any]) -> CaseResult:
    """Dispatch a registry case (argv or shell completion)."""
    category = str(case.get("category") or "cli_contract")
    case_id = str(case.get("id") or "unknown")
    if case.get("kind") == "completion_shell":
        return run_completion_shell(root, binary, case)
    fixture_rel = case.get("fixture")
    fixture: Path | None = None
    if fixture_rel:
        fixture = root / FIXTURES_REL / str(fixture_rel)
        if not fixture.is_dir():
            return CaseResult(
                case_id,
                category,
                False,
                None,
                f"missing fixture {fixture}",
            )
    args = substitute_args(list(case["args"]), fixture)
    case_copy = dict(case)
    case_copy["args"] = args
    with tempfile.TemporaryDirectory(prefix="vlz-cli-contract-") as tmp:
        tmp_path = Path(tmp)
        if fixture is not None:
            scan_root = tmp_path / "scan"
            materialize_fixture_tree(fixture, scan_root)
            case_copy["args"] = substitute_args(list(case["args"]), scan_root)
        return run_argv(binary, case_copy, tmp_path)


def run_completion_shell(
    root: Path, binary: Path, case: dict[str, Any]
) -> CaseResult:
    """Run a real-shell completion check, skipping Windows."""
    category = str(case.get("category") or "completion")
    case_id = str(case.get("id") or "unknown")
    shell = str(case.get("shell") or "")
    if sys.platform == "win32":
        return CaseResult(
            case_id,
            category,
            True,
            0,
            "skipped on Windows (generate-completions + archive layout only)",
        )
    if shell == "bash":
        return _bash_completion(root, binary, case)
    if shell == "zsh":
        return _zsh_completion(root, binary, case)
    if shell == "fish":
        return _fish_completion(root, binary, case)
    return CaseResult(case_id, category, False, None, f"unknown shell {shell}")


def _shell_bin(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    fallback = Path("/bin") / name
    if fallback.is_file():
        return str(fallback)
    return None


def _bash_completion(
    root: Path, binary: Path, case: dict[str, Any]
) -> CaseResult:
    case_id = str(case["id"])
    script = root / "completions" / "vlz.bash"
    if not script.is_file():
        return CaseResult(
            case_id, "completion", False, None, "missing completions/vlz.bash"
        )
    bash = _shell_bin("bash")
    if bash is None:
        return CaseResult(case_id, "completion", True, 0, "bash not installed")
    helper = r"""
set -euo pipefail
COMP_SCRIPT="$1"
# shellcheck disable=SC1090
source "$COMP_SCRIPT"
COMP_LINE="vlz "
COMP_POINT=${#COMP_LINE}
COMP_WORDS=(vlz "")
COMP_CWORD=1
if declare -F _vlz >/dev/null; then
  comp_fn=_vlz
elif declare -F _vlz_cli >/dev/null; then
  comp_fn=_vlz_cli
else
  echo "no bash completion function" >&2
  exit 1
fi
# complete -F supplies $1 command, $2 current word, $3 previous word.
"$comp_fn" "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" \
  "${COMP_WORDS[$((COMP_CWORD - 1))]}"
# Bash before 4.4 treats an empty array as unset under nounset.
for reply in ${COMPREPLY[@]+"${COMPREPLY[@]}"}; do
  printf '%s\n' "$reply"
done
"""
    try:
        proc = subprocess.run(  # nosec B603
            [bash, "-c", helper, "bash", str(script)],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PATH": str(binary.parent)},
        )
    except OSError as exc:
        return CaseResult(case_id, "completion", False, None, str(exc))
    out = proc.stdout or ""
    missing = [
        str(needle)
        for needle in case.get("stdout_contains") or []
        if str(needle) not in out
    ]
    ok = proc.returncode == 0 and not missing
    if proc.returncode != 0:
        detail = proc.stderr or f"exit {proc.returncode}"
    else:
        detail = "; ".join(
            f"completion missing {needle!r}" for needle in missing
        )
    return CaseResult(case_id, "completion", ok, proc.returncode, detail)


def _zsh_completion(
    root: Path, _binary: Path, case: dict[str, Any]
) -> CaseResult:
    case_id = str(case["id"])
    script = root / "completions" / "_vlz"
    if not script.is_file():
        return CaseResult(
            case_id, "completion", False, None, "missing completions/_vlz"
        )
    zsh = _shell_bin("zsh")
    if zsh is None:
        return CaseResult(case_id, "completion", True, 0, "zsh not installed")
    try:
        proc = subprocess.run(  # nosec B603
            [
                zsh,
                "-c",
                "fpath=($1 $fpath); autoload -U compinit; "
                "compinit -u; echo ok",
                "zsh",
                str(script.parent),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return CaseResult(case_id, "completion", False, None, str(exc))
    ok = proc.returncode == 0 and "ok" in (proc.stdout or "")
    return CaseResult(
        case_id,
        "completion",
        ok,
        proc.returncode,
        "" if ok else (proc.stderr or "zsh completion init failed"),
    )


def _fish_completion(
    root: Path, _binary: Path, case: dict[str, Any]
) -> CaseResult:
    case_id = str(case["id"])
    script = root / "completions" / "vlz.fish"
    if not script.is_file():
        return CaseResult(
            case_id, "completion", False, None, "missing completions/vlz.fish"
        )
    fish = _shell_bin("fish")
    if fish is None:
        return CaseResult(case_id, "completion", True, 0, "fish not installed")
    try:
        proc = subprocess.run(  # nosec B603
            [fish, "-c", f"source '{script}'; echo ok"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return CaseResult(case_id, "completion", False, None, str(exc))
    ok = proc.returncode == 0 and "ok" in (proc.stdout or "")
    return CaseResult(
        case_id,
        "completion",
        ok,
        proc.returncode,
        "" if ok else (proc.stderr or "fish completion source failed"),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI contract runner flags."""
    parser = argparse.ArgumentParser(description="Run vlz CLI contract cases")
    parser.add_argument("--binary", required=True, help="Path to vlz binary")
    parser.add_argument(
        "--mode",
        choices=VALID_MODES,
        default="smoke",
        help="smoke (PR/release) or full (nightly)",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Repository root (default: inferred)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Return 0 on success, 1 on case failure, 2 on usage."""
    args = parse_args(argv)
    binary = Path(args.binary).expanduser()
    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2
    root = Path(args.root).resolve() if args.root else repo_root_from()
    registry = load_registry(root)
    errors = validate_registry(root, registry)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 2
    try:
        cases = cases_for_mode(registry, args.mode)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    results = [run_case(root, binary, case) for case in cases]
    failed = [item for item in results if not item.ok]
    for item in results:
        print(item.summary())
    if failed:
        print(f"{len(failed)}/{len(results)} cases failed", file=sys.stderr)
        return 1
    print(f"{len(results)} cases passed ({args.mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
