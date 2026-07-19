# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract: root Makefile check and check-fast must list deny-check (NFR-009, SEC-012)."""

import re

from tests.scripts.repo_root import repo_root


def _extract_prerequisite_block(makefile_text: str, target: str) -> str:
    """Join prerequisite lines for target (handles backslash continuations)."""
    lines = makefile_text.splitlines()
    prefix = f"{target}:"
    start = None
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            start = i
            break
    if start is None:
        raise AssertionError(f"Makefile has no {prefix} target")

    chunk: list[str] = [lines[start]]
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if line.startswith("\t"):
            break
        if line.strip() == "":
            i += 1
            continue
        if line.lstrip().startswith("#"):
            i += 1
            continue
        if line.startswith(" "):
            chunk.append(line)
            i += 1
            continue
        break

    return " ".join(s.strip() for s in chunk)


def test_check_target_includes_deny_check() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "check-parallel")
    assert "deny-check" in block.split(), (
        "make check must depend on deny-check (cargo deny check)"
    )


def test_check_fast_target_includes_deny_check() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    block = _extract_prerequisite_block(text, "check-fast-parallel")
    tokens = block.replace("\\", " ").split()
    assert "deny-check" in tokens, (
        "make check-fast must depend on deny-check (quick local gate; CI runs "
        "make -j check)"
    )


def test_check_serializes_check_headers_before_parallel() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert re.search(
        r"^check: setup\n\t@\$\(MAKE\) check-headers\n"
        r"\t@\$\(MAKE\) --output-sync=target -k -j check-parallel\n"
        r"\t@\$\(MAKE\) fuzz-then-coverage",
        text,
        re.MULTILINE,
    ), (
        "make check must run check-headers before parallel check-parallel "
        "(reuse lint races cargo under target/) and fuzz-then-coverage after "
        "parallel gates (llvm-cov races other cargo jobs)"
    )
    block = _extract_prerequisite_block(text, "check-parallel")
    tokens = block.replace("\\", " ").split()
    assert "check-headers" not in tokens


def test_check_fast_serializes_check_headers_before_parallel() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert re.search(
        r"^check-fast: setup\n\t@\$\(MAKE\) check-headers\n"
        r"\t@\$\(MAKE\) --output-sync=target -k -j check-fast-parallel",
        text,
        re.MULTILINE,
    ), (
        "make check-fast must run check-headers before parallel "
        "check-fast-parallel (reuse lint races cargo under target/)"
    )
    block = _extract_prerequisite_block(text, "check-fast-parallel")
    tokens = block.replace("\\", " ").split()
    assert "check-headers" not in tokens
