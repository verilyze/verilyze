# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Benchmark gate helpers (NFR-001, FR-029)."""

import json
import re
import subprocess
from pathlib import Path

import pytest

from tests.scripts.repo_root import repo_root

BENCHMARK_METRICS_RS = (
    repo_root() / "crates" / "core" / "vlz" / "src" / "benchmark_metrics.rs"
)
BENCHMARK_CONSTANTS_SH = (
    repo_root() / "scripts" / "lib" / "benchmark_constants.sh"
)


def parse_benchmark_max_ms_from_rust() -> int:
    text = BENCHMARK_METRICS_RS.read_text(encoding="utf-8")
    match = re.search(
        r"pub const BENCHMARK_MAX_MS: u64 = ([0-9_]+);",
        text,
    )
    assert match is not None, "BENCHMARK_MAX_MS not found in benchmark_metrics.rs"
    return int(match.group(1).replace("_", ""))


def parse_duration_ms_from_stdout(stdout: str) -> int:
    line = next((ln for ln in stdout.splitlines() if '"benchmark"' in ln), "")
    if not line:
        raise ValueError("no benchmark json line on stdout")
    data = json.loads(line)
    return int(data["benchmark"]["duration_ms"])


class TestBenchmarkConstants:
    def test_rust_benchmark_max_ms_is_positive(self) -> None:
        assert parse_benchmark_max_ms_from_rust() > 0

    def test_shell_constants_parse_max_ms(self) -> None:
        root = repo_root()
        proc = subprocess.run(
            [
                "bash",
                "-c",
                (
                    f'ROOT="{root}"; '
                    f'source "{BENCHMARK_CONSTANTS_SH}"; '
                    'echo "$BENCHMARK_MAX_MS"'
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=root,
        )
        shell_value = int(proc.stdout.strip())
        assert shell_value == parse_benchmark_max_ms_from_rust()


class TestBenchmarkFixtureGenerator:
    def test_generate_fixture_writes_manifest_dirs(self, tmp_path: Path) -> None:
        script = repo_root() / "scripts" / "generate-benchmark-fixture.sh"
        subprocess.run(
            [str(script), str(tmp_path), "5"],
            check=True,
            cwd=repo_root(),
        )
        manifests = list(tmp_path.glob("pkg*/requirements.txt"))
        assert len(manifests) == 5


class TestBenchmarkDurationParsing:
    def test_parse_duration_from_sample_stdout(self) -> None:
        stdout = (
            "No vulnerabilities found.\n"
            '{"benchmark":{"duration_ms":123,"cpu_percent":0,"mem_mb":10}}\n'
        )
        assert parse_duration_ms_from_stdout(stdout) == 123

    def test_parse_duration_missing_line_raises(self) -> None:
        with pytest.raises(ValueError, match="no benchmark json"):
            parse_duration_ms_from_stdout("no metrics here\n")
