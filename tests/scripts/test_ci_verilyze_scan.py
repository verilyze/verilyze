# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/ci-verilyze-scan.sh (SEC-015 CI self-scan)."""

import json
import os
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_SCAN_SCRIPT = _ROOT / "scripts" / "ci-verilyze-scan.sh"
_METRICS_LIB = _ROOT / "scripts" / "lib" / "ci-verilyze-scan-metrics.sh"


def _write_fake_vlz(
    path: Path,
    *,
    exit_code: int = 0,
    arg_log: Path | None = None,
) -> None:
    log_path = str(arg_log) if arg_log else "/dev/null"
    path.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
echo "vlz 0.5.0"
while (($#)); do
  case "$1" in
    --reachability-mode)
      echo "reachability_mode=$2" >> "{log_path}"
      shift 2
      ;;
    --report|--summary-file)
      spec="$2"
      target="${{spec#*:}}"
      case "$spec" in
        json:*)
          printf '%s\\n' '{{"findings":[{{"package":"pkg"}}]}}' > "$target"
          ;;
        sarif:*)
          printf '%s\\n' '{{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{{"tool":{{"driver":{{"name":"vlz"}}}},"results":[{{"ruleId":"CVE-TEST-1","locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"Cargo.toml"}},"region":{{"startLine":3}}}},"properties":{{"location_kind":"declaration"}}}}]}}]}}]}}' > "$target"
          ;;
      esac
      shift 2
      ;;
    --output|-o)
      printf '%s\\n' '{{"findings":[{{"package":"pkg"}}]}}' > "$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
exit {exit_code}
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_scan(
    tmp_path: Path,
    *,
    env: dict[str, str] | None = None,
    fake_exit: int = 0,
) -> subprocess.CompletedProcess[str]:
    fake_vlz = tmp_path / "vlz"
    arg_log = tmp_path / "vlz-args.log"
    _write_fake_vlz(fake_vlz, exit_code=fake_exit, arg_log=arg_log)
    report_json = tmp_path / "report.json"
    report_sarif = tmp_path / "report.sarif"
    gh_output = tmp_path / "github-output"
    merged = os.environ.copy()
    merged.update(
        {
            "VLZ_BIN": str(fake_vlz),
            "REPORT_JSON": str(report_json),
            "REPORT_SARIF": str(report_sarif),
            "GITHUB_OUTPUT": str(gh_output),
            "GITHUB_WORKSPACE": str(_ROOT),
        },
    )
    if env:
        merged.update(env)
    proc = subprocess.run(
        [str(_SCAN_SCRIPT)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )
    proc.arg_log = arg_log.read_text(encoding="utf-8") if arg_log.is_file() else ""
    proc.gh_output = gh_output.read_text(encoding="utf-8") if gh_output.is_file() else ""
    proc.report_json = report_json
    proc.report_sarif = report_sarif
    return proc


class TestCiVerilyzeScan:
    def test_requires_vlz_bin(self) -> None:
        proc = subprocess.run(
            [str(_SCAN_SCRIPT)],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={
                k: v
                for k, v in os.environ.items()
                if k not in {"VLZ_BIN", "REPORT_JSON", "REPORT_SARIF"}
            },
        )
        assert proc.returncode != 0
        assert "VLZ_BIN is required" in proc.stderr

    def test_default_reachability_mode_is_tier_b(self, tmp_path: Path) -> None:
        proc = _run_scan(tmp_path)
        assert proc.returncode == 0
        assert "reachability_mode=tier-b" in proc.arg_log

    def test_reachability_mode_env_override(self, tmp_path: Path) -> None:
        proc = _run_scan(
            tmp_path,
            env={"VLZ_REACHABILITY_MODE": "best-available"},
        )
        assert proc.returncode == 0
        assert "reachability_mode=best-available" in proc.arg_log

    def test_propagates_scan_exit_code(self, tmp_path: Path) -> None:
        proc = _run_scan(tmp_path, fake_exit=86)
        assert proc.returncode == 86
        assert "scan_exit=86" in proc.gh_output

    def test_writes_reports_on_exit_86(self, tmp_path: Path) -> None:
        proc = _run_scan(tmp_path, fake_exit=86)
        assert proc.report_json.is_file()
        assert proc.report_sarif.is_file()

    def test_logs_finding_and_sarif_counts(self, tmp_path: Path) -> None:
        proc = _run_scan(tmp_path)
        assert proc.returncode == 0
        assert "finding_count=1" in proc.gh_output
        assert "sarif_result_count=1" in proc.gh_output
        assert "scan_duration_seconds=" in proc.gh_output


class TestCiVerifyVlzReleaseVersion:
    def test_rejects_binary_below_minimum(self, tmp_path: Path) -> None:
        fake_vlz = tmp_path / "vlz"
        fake_vlz.write_text(
            '#!/usr/bin/env bash\necho "vlz 0.4.0"\n',
            encoding="utf-8",
        )
        fake_vlz.chmod(0o755)
        proc = subprocess.run(
            [
                str(_ROOT / "scripts" / "ci-verify-vlz-release-version.sh"),
                str(fake_vlz),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode != 0
        assert "older than required" in proc.stderr

    def test_accepts_binary_at_minimum(self, tmp_path: Path) -> None:
        fake_vlz = tmp_path / "vlz"
        fake_vlz.write_text(
            '#!/usr/bin/env bash\necho "vlz 0.5.0"\n',
            encoding="utf-8",
        )
        fake_vlz.chmod(0o755)
        proc = subprocess.run(
            [
                str(_ROOT / "scripts" / "ci-verify-vlz-release-version.sh"),
                str(fake_vlz),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0


class TestCiEnforceScanExit:
    def test_propagates_valid_exit_code(self) -> None:
        proc = subprocess.run(
            [str(_ROOT / "scripts" / "ci-enforce-scan-exit.sh")],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "SCAN_EXIT": "86"},
        )
        assert proc.returncode == 86

    def test_rejects_non_numeric_exit_code(self) -> None:
        proc = subprocess.run(
            [str(_ROOT / "scripts" / "ci-enforce-scan-exit.sh")],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "SCAN_EXIT": "86; rm -rf /"},
        )
        assert proc.returncode == 1
        assert "invalid scan exit code" in proc.stderr


class TestCiVerilyzeScanMetrics:
    def test_metrics_lib_counts_json_and_sarif(self, tmp_path: Path) -> None:
        report_json = tmp_path / "report.json"
        report_sarif = tmp_path / "report.sarif"
        report_json.write_text(
            json.dumps({"findings": [{"package": "a"}, {"package": "b"}]}),
            encoding="utf-8",
        )
        report_sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {"results": [{"ruleId": "CVE-1"}, {"ruleId": "CVE-2"}]},
                        {"results": [{"ruleId": "CVE-3"}]},
                    ],
                },
            ),
            encoding="utf-8",
        )
        gh_output = tmp_path / "out"
        proc = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{_METRICS_LIB}"; '
                f'ci_verilyze_emit_scan_metrics "{report_json}" "{report_sarif}" 12 0',
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "GITHUB_OUTPUT": str(gh_output)},
        )
        assert proc.returncode == 0
        output = gh_output.read_text(encoding="utf-8")
        assert "finding_count=2" in output
        assert "sarif_result_count=3" in output
        assert "scan_duration_seconds=12" in output
        assert "scan_exit=0" in output
