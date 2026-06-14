#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Enforce Python 3.11+ modern style for scripts and script tests."""

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

PYTHON_STYLE_DIRS = ("scripts", "tests/scripts")

BANNED_TYPING_NAMES = frozenset(
    {
        "Dict",
        "FrozenSet",
        "List",
        "Optional",
        "Set",
        "Tuple",
        "Union",
    }
)

TYPING_EXTENSIONS_REDIRECT_TO_TYPING = frozenset(
    {
        "Annotated",
        "Concatenate",
        "Final",
        "Literal",
        "LiteralString",
        "Never",
        "NotRequired",
        "ParamSpec",
        "Protocol",
        "Required",
        "Self",
        "TypeAlias",
        "TypeGuard",
        "TypedDict",
        "TypeVarTuple",
        "Unpack",
        "assert_never",
        "assert_type",
        "reveal_type",
        "runtime_checkable",
    }
)


@dataclass(frozen=True)
class StyleViolation:
    """A single modern-style policy violation."""

    path: Path
    line: int
    rule: str
    detail: str

    def format(self) -> str:
        """Return a single-line violation message."""
        rel = self.path.as_posix()
        return f"{rel}:{self.line}: {self.rule} {self.detail}"


class _StyleVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[StyleViolation] = []
        self._typing_aliases: set[str] = set()
        self._typing_extensions_aliases: set[str] = set()

    # pylint: disable=invalid-name
    def visit_Import(self, node: ast.Import) -> None:
        """Record aliases for typing module imports."""
        for alias in node.names:
            if alias.name == "typing":
                self._typing_aliases.add(alias.asname or "typing")
            if alias.name == "typing_extensions":
                self._typing_extensions_aliases.add(
                    alias.asname or "typing_extensions"
                )
        self.generic_visit(node)

    # pylint: disable=invalid-name
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Flag banned __future__, typing, and typing_extensions imports."""
        if node.module == "__future__":
            for alias in node.names:
                self._add(
                    node,
                    "future-import",
                    f"remove `from __future__ import {alias.name}`",
                )
            return

        if node.module == "typing":
            for alias in node.names:
                if alias.name in BANNED_TYPING_NAMES:
                    self._add(
                        node,
                        "legacy-typing",
                        (
                            "use built-in generics or `X | Y` instead of "
                            f"`typing.{alias.name}`"
                        ),
                    )
            return

        if node.module == "typing_extensions":
            for alias in node.names:
                if alias.name in TYPING_EXTENSIONS_REDIRECT_TO_TYPING:
                    self._add(
                        node,
                        "typing-extensions",
                        (
                            f"import `{alias.name}` from `typing` on "
                            "Python 3.11+, not `typing_extensions`"
                        ),
                    )
            return

        self.generic_visit(node)

    # pylint: disable=invalid-name
    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Flag banned typing and typing_extensions attribute access."""
        if isinstance(node.value, ast.Name):
            if (
                node.value.id in self._typing_aliases
                and node.attr in BANNED_TYPING_NAMES
            ):
                self._add(
                    node,
                    "legacy-typing",
                    (
                        "use built-in generics or `X | Y` instead of "
                        f"`{node.value.id}.{node.attr}`"
                    ),
                )
            if (
                node.value.id in self._typing_extensions_aliases
                and node.attr in TYPING_EXTENSIONS_REDIRECT_TO_TYPING
            ):
                self._add(
                    node,
                    "typing-extensions",
                    (
                        f"import `{node.attr}` from `typing` on Python 3.11+, "
                        f"not `{node.value.id}.{node.attr}`"
                    ),
                )
        self.generic_visit(node)

    def _add(self, node: ast.AST, rule: str, detail: str) -> None:
        line = getattr(node, "lineno", 1)
        self.violations.append(
            StyleViolation(path=self.path, line=line, rule=rule, detail=detail)
        )


def find_violations_in_source(source: str, path: Path) -> list[str]:
    """Return formatted violations for a single source string."""
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [f"{path.as_posix()}:{exc.lineno or 1}: syntax-error {exc.msg}"]
    visitor = _StyleVisitor(path)
    visitor.visit(tree)
    return [item.format() for item in visitor.violations]


def iter_python_files(repo_root: Path) -> list[Path]:
    """Collect Python files under the configured style directories."""
    files: list[Path] = []
    for relative in PYTHON_STYLE_DIRS:
        root = repo_root / relative
        if not root.is_dir():
            continue
        files.extend(sorted(root.rglob("*.py")))
    return files


def find_violations(repo_root: Path) -> list[str]:
    """Return formatted violations for all in-scope Python files."""
    messages: list[str] = []
    for path in iter_python_files(repo_root):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            rel = path.relative_to(repo_root)
            messages.append(f"{rel.as_posix()}:1: read-error {exc}")
            continue
        rel_path = path.relative_to(repo_root)
        messages.extend(find_violations_in_source(source, rel_path))
    return messages


def main(_argv: list[str] | None = None) -> int:
    """CLI entry point; exit 1 when modern-style violations are found."""
    repo_root = Path(__file__).resolve().parent.parent
    violations = find_violations(repo_root)
    if violations:
        for message in violations:
            print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
