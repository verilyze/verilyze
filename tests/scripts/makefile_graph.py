# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Parse root Makefile targets for check-reachable brief-mode recipe contracts."""

import re
from dataclasses import dataclass, field

CHECK_ROOTS = ("check", "check-fast", "check-pr")

MAKE_FLAGS = frozenset(
    {
        "-C",
        "-f",
        "-j",
        "-k",
        "--output-sync=target",
        "--always-make",
        "--no-print-directory",
    }
)

TOOL_PATTERN = re.compile(
    r"(?:"
    r"\bpython3?\b"
    r"|\bcargo\b"
    r"|\bpip\b"
    r"|\$\(SCRIPTS_DIR\)"
    r"|/scripts/[^\s'\"]+\.sh"
    r"|\$\([A-Z_]+\)/[^\s'\"]+\.sh"
    r")",
    re.IGNORECASE,
)

MAKE_RUN_LEAF_PATTERN = re.compile(r"^\s*\$\(MAKE_RUN_LEAF\)(?:\s|$)")
MAKE_RECURSE_PATTERN = re.compile(r"\$\(MAKE\)(?!_RUN_LEAF)")
LINT_PYTHON_PATTERN = re.compile(r"^\s*\$\(LINT_PYTHON_SCRIPT\)\s*$")


@dataclass
class MakefileTarget:
    """One Makefile target with prerequisites and recipe commands."""

    name: str
    prerequisites: list[str] = field(default_factory=list)
    recipes: list[str] = field(default_factory=list)


@dataclass
class BriefRecipeViolation:
    """A check-reachable recipe that breaks brief-mode quiet rules."""

    target: str
    recipe: str
    reason: str


def _strip_inline_comment(line: str) -> str:
    """Remove trailing # comments outside of quotes (Makefile heuristic)."""
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index].rstrip()
    return line.rstrip()


def _is_target_header(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    if line.startswith("\t") or line.startswith(" "):
        return False
    if ":=" in stripped or "?=" in stripped or "+=" in stripped:
        return False
    if stripped.startswith(".") and ":" in stripped:
        return True
    if ":" not in stripped:
        return False
    before_colon = stripped.split(":", 1)[0]
    return bool(before_colon.strip())


def _parse_prerequisites(header: str) -> tuple[str, list[str]]:
    name, _, prereq_text = header.partition(":")
    tokens = re.split(r"\s+", prereq_text.strip())
    return name.strip(), [token for token in tokens if token]


def parse_makefile(text: str) -> dict[str, MakefileTarget]:
    """Return target name to parsed target for recipe/prerequisite analysis."""
    lines = text.splitlines()
    targets: dict[str, MakefileTarget] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not _is_target_header(line):
            index += 1
            continue

        header_parts = [_strip_inline_comment(line)]
        index += 1
        while index < len(lines):
            next_line = lines[index]
            if next_line.startswith("\t"):
                break
            if next_line.strip() == "" or next_line.lstrip().startswith("#"):
                index += 1
                continue
            if next_line.startswith(" ") and ":" not in next_line.split("#", 1)[0]:
                header_parts.append(_strip_inline_comment(next_line.strip()))
                index += 1
                continue
            break

        header = " ".join(part for part in header_parts if part)
        name, prerequisites = _parse_prerequisites(header)
        recipes: list[str] = []
        while index < len(lines) and lines[index].startswith("\t"):
            command_parts: list[str] = []
            while index < len(lines):
                line = lines[index]
                if not line.startswith("\t"):
                    break
                command_parts.append(line[1:])
                index += 1
                if not line.rstrip().endswith("\\"):
                    break
            joined = " ".join(part.strip() for part in command_parts).strip()
            if joined:
                recipes.append(joined)
        targets[name] = MakefileTarget(name=name, prerequisites=prerequisites, recipes=recipes)
    return targets


def _join_recipe_commands(recipes: list[str]) -> list[tuple[str, bool]]:
    """Return (command, starts_with_at) for each Makefile recipe command."""
    commands: list[tuple[str, bool]] = []
    for recipe in recipes:
        starts_with_at = recipe.startswith("@")
        commands.append((recipe.lstrip("@").strip(), starts_with_at))
    return commands


def extract_make_targets(command: str) -> list[str]:
    """Extract nested GNU make target names from a $(MAKE) recipe command."""
    if not MAKE_RECURSE_PATTERN.search(command):
        return []
    targets: list[str] = []
    for match in MAKE_RECURSE_PATTERN.finditer(command):
        remainder = command[match.end() :].strip()
        tokens = re.split(r"\s+", remainder)
        index = 0
        while index < len(tokens):
            token = tokens[index].strip()
            if not token:
                index += 1
                continue
            if token in MAKE_FLAGS:
                index += 1
                continue
            if token.startswith("-C") or token.startswith("-f"):
                index += 1
                continue
            if token.startswith("-") and "=" in token:
                index += 1
                continue
            if token.startswith('"') and token.endswith('"'):
                index += 1
                continue
            targets.append(token)
            break
    return targets


def _is_venv_health_skip(command: str) -> bool:
    """True for venv bootstrap 'already installed' guard recipes."""
    stripped = command.strip()
    return stripped.startswith("if [ -x ") and "exit 0" in stripped and stripped.rstrip().endswith("fi")


def _is_quiet_builtin(command: str) -> bool:
    if LINT_PYTHON_PATTERN.match(command):
        return True
    if _is_venv_health_skip(command):
        return True
    first = command.split("&&", 1)[0].strip()
    quiet_prefixes = (
        "mkdir ",
        "rm ",
        "touch ",
        "test ",
        "command -v ",
        ": ",
    )
    if any(first.startswith(prefix) for prefix in quiet_prefixes):
        return True
    if first == ":":
        return True
    return False


def classify_recipe_command(
    target: str, command: str, *, starts_with_at: bool
) -> BriefRecipeViolation | None:
    """Return a violation when a check-reachable recipe breaks brief rules."""
    if target == "help":
        return None
    if not starts_with_at:
        return BriefRecipeViolation(
            target=target,
            recipe=command,
            reason="recipe must start with @ to suppress GNU Make echo in brief CI",
        )
    stripped = command.lstrip()
    if MAKE_RUN_LEAF_PATTERN.match(stripped):
        return None
    if MAKE_RECURSE_PATTERN.search(stripped):
        return None
    if _is_quiet_builtin(stripped):
        return None
    if TOOL_PATTERN.search(stripped):
        return BriefRecipeViolation(
            target=target,
            recipe=command,
            reason=(
                "tool output must run via $(MAKE_RUN_LEAF) for brief "
                "[RUN]/[PASS] capture (or be a recursive $(MAKE) target)"
            ),
        )
    return None


def walk_check_reachable(targets: dict[str, MakefileTarget]) -> set[str]:
    """Depth-first collect targets reachable from check/check-fast/check-pr."""
    seen: set[str] = set()
    stack = list(CHECK_ROOTS)

    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        target = targets.get(name)
        if target is None:
            continue
        for prereq in target.prerequisites:
            if prereq not in seen:
                stack.append(prereq)
        for recipe in target.recipes:
            for nested in extract_make_targets(recipe):
                if nested not in seen:
                    stack.append(nested)
            commands = _join_recipe_commands([recipe])
            for command, _starts_with_at in commands:
                for nested in extract_make_targets(command):
                    if nested not in seen:
                        stack.append(nested)
    return seen


def find_brief_recipe_violations(text: str) -> list[BriefRecipeViolation]:
    """Return all brief-mode recipe violations under check roots."""
    targets = parse_makefile(text)
    reachable = walk_check_reachable(targets)
    violations: list[BriefRecipeViolation] = []
    for name in sorted(reachable):
        target = targets.get(name)
        if target is None:
            continue
        commands = _join_recipe_commands(target.recipes)
        for command, starts_with_at in commands:
            violation = classify_recipe_command(
                name, command, starts_with_at=starts_with_at
            )
            if violation is not None:
                violations.append(violation)
    return violations
