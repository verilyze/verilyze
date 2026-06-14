#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Evaluate OBS build result XML for release wait logic."""

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
import xml.etree.ElementTree as ET  # nosec B405

_FAILED_STATUS_CODES = frozenset(
    {
        "failed",
        "broken",
        "unresolvable",
        "cancelled",
    }
)

_PENDING_STATUS_CODES = frozenset(
    {
        "building",
        "scheduled",
        "blocked",
        "dispatching",
        "signing",
        "finished",
        "unknown",
    }
)


@dataclass(frozen=True)
class BuildResultsSummary:
    """Aggregate OBS build state for configured repositories."""

    all_succeeded: bool
    any_failed: bool
    pending: int
    matched: int
    failures: tuple[str, ...]
    pending_targets: tuple[str, ...]


def _target_label(repository: str, arch: str) -> str:
    return f"{repository}/{arch}"


def _classify_status(
    repository: str,
    arch: str,
    code: str,
) -> tuple[str, str | None]:
    """Return ('succeeded'|'failed'|'pending', optional detail label)."""
    label = _target_label(repository, arch)
    if code == "succeeded":
        return ("succeeded", None)
    if code in _FAILED_STATUS_CODES:
        return ("failed", f"{label}:{code}")
    if code in _PENDING_STATUS_CODES or not code:
        pending_code = code or "pending"
        return ("pending", f"{label}:{pending_code}")
    return ("pending", f"{label}:{code}")


def _process_result(
    result: ET.Element,
    *,
    package: str,
    repo_set: set[str],
) -> tuple[int, int, int, list[str], list[str]]:
    """Return matched, succeeded, pending, failures, pending_targets deltas."""
    repository = result.get("repository", "")
    if repository not in repo_set:
        return (0, 0, 0, [], [])

    arch = result.get("arch", "")
    status = result.find("status")
    if status is None:
        return (0, 0, 1, [], [_target_label(repository, arch)])
    if status.get("package") not in (None, package):
        return (0, 0, 0, [], [])

    code = (status.get("code") or "").strip()
    outcome, detail = _classify_status(repository, arch, code)
    matched = 1
    succeeded = 1 if outcome == "succeeded" else 0
    pending = 0
    failures: list[str] = []
    pending_targets: list[str] = []
    if outcome == "failed" and detail is not None:
        failures = [detail]
    elif detail is not None:
        pending = 1
        pending_targets = [detail]
    return (matched, succeeded, pending, failures, pending_targets)


def evaluate_build_results(
    xml_text: str,
    *,
    package: str,
    repositories: tuple[str, ...],
) -> BuildResultsSummary:
    """Return build state for package builds in the given repositories."""
    if not repositories:
        msg = "repositories must not be empty"
        raise ValueError(msg)

    repo_set = set(repositories)
    # XML comes from authenticated OBS API responses, not arbitrary user input.
    root = ET.fromstring(xml_text)  # nosec B314
    matched = 0
    pending = 0
    failures: list[str] = []
    pending_targets: list[str] = []
    succeeded = 0

    for result in root.findall("result"):
        delta = _process_result(
            result,
            package=package,
            repo_set=repo_set,
        )
        matched += delta[0]
        succeeded += delta[1]
        pending += delta[2]
        failures.extend(delta[3])
        pending_targets.extend(delta[4])

    expected = matched
    all_succeeded = expected > 0 and succeeded == expected and pending == 0
    return BuildResultsSummary(
        all_succeeded=all_succeeded,
        any_failed=bool(failures),
        pending=pending,
        matched=matched,
        failures=tuple(failures),
        pending_targets=tuple(pending_targets),
    )


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def format_shell_summary(summary: BuildResultsSummary) -> str:
    """Emit shell assignments for use from obs-wait-for-builds.sh."""
    failures = ",".join(summary.failures)
    pending_targets = ",".join(summary.pending_targets)
    lines = [
        f"ALL_SUCCEEDED={1 if summary.all_succeeded else 0}",
        f"ANY_FAILED={1 if summary.any_failed else 0}",
        f"PENDING={summary.pending}",
        f"MATCHED={summary.matched}",
        f"FAILURES={_shell_quote(failures)}",
        f"PENDING_TARGETS={_shell_quote(pending_targets)}",
    ]
    return "\n".join(lines)


def main() -> int:
    """CLI entry point for shell polling integration."""
    parser = argparse.ArgumentParser(
        description="Evaluate OBS build result XML.",
    )
    parser.add_argument("--package", required=True)
    parser.add_argument("--repositories", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--xml", help="OBS _result XML text")
    group.add_argument("--xml-file", help="Path to OBS _result XML file")
    args = parser.parse_args()
    if args.xml_file:
        xml_text = Path(args.xml_file).read_text(encoding="utf-8")
    else:
        xml_text = args.xml
    repositories = tuple(
        repo.strip() for repo in args.repositories.split(",") if repo.strip()
    )
    summary = evaluate_build_results(
        xml_text,
        package=args.package,
        repositories=repositories,
    )
    sys.stdout.write(format_shell_summary(summary))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
