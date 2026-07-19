# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Validate vlz JSON report schema and fixtures (DOC-005, NFR-014)."""

import json
import subprocess
import tempfile
from pathlib import Path

import jsonschema
import pytest

from tests.scripts.repo_root import repo_root

SCHEMA_PATH = repo_root() / "schemas" / "v1" / "report.json"
GOLDEN_PATH = (
    repo_root() / "tests" / "scripts" / "fixtures" / "report-schema-golden.json"
)
REPORT_JSON_SCHEMA_ID = (
    "https://github.com/verilyze/verilyze/schemas/v1/report.json"
)


def _load_schema() -> dict:
    with SCHEMA_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_vlz_bin() -> Path:
    env_bin = __import__("os").environ.get("VLZ_BIN")
    if env_bin:
        candidate = Path(env_bin)
        if candidate.is_file():
            return candidate
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=repo_root(),
        check=True,
        capture_output=True,
        text=True,
    )
    target_dir = Path(json.loads(proc.stdout)["target_directory"])
    for sub in ("release", "debug"):
        candidate = target_dir / sub / "vlz"
        if candidate.is_file():
            return candidate
    raise RuntimeError("vlz binary not found; run make release or set VLZ_BIN")


class TestReportJsonSchema:
    """Schema file and golden fixture conformance."""

    def test_schema_file_is_valid_json_schema(self) -> None:
        schema = _load_schema()
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["$id"] == REPORT_JSON_SCHEMA_ID

    def test_golden_fixture_validates_against_schema(self) -> None:
        schema = _load_schema()
        document = _load_json(GOLDEN_PATH)
        jsonschema.validate(document, schema)

    def test_live_scan_output_validates_against_schema(self) -> None:
        vlz = _resolve_vlz_bin()
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            subprocess.run(
                [
                    str(vlz),
                    "scan",
                    tmp,
                    "--offline",
                    "--benchmark",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                ],
                cwd=repo_root(),
                check=True,
                capture_output=True,
                text=True,
            )
            document = _load_json(report_path)
            schema = _load_schema()
            jsonschema.validate(document, schema)
