# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: CI check job caches, linker env, and lazy AFL preflight."""

import re
from pathlib import Path

from tests.scripts.repo_root import repo_root

_CI = repo_root() / ".github" / "workflows" / "ci.yml"


def _check_job_block() -> str:
    text = _CI.read_text(encoding="utf-8")
    start = text.index("  check:")
    end = text.index("  coverage-pr-comment:", start)
    return text[start:end]


def _cargo_deny_version() -> str:
    block = _check_job_block()
    match = re.search(r'CARGO_DENY_VERSION: "([^"]+)"', block)
    assert match is not None, "check job must pin CARGO_DENY_VERSION for Renovate"
    return match.group(1)


def test_check_job_sets_linker_env_at_job_level() -> None:
    block = _check_job_block()
    assert "env:" in block.split("steps:")[0]
    assert "CC: gcc" in block
    assert "RUSTFLAGS: -Clink-arg=-fuse-ld=bfd" in block


def test_check_job_rust_cache_uses_shared_key() -> None:
    block = _check_job_block()
    assert "shared-key: check" in block


def test_check_job_fuzz_preflight_before_afl_install() -> None:
    block = _check_job_block()
    pre = block.index("Fuzz preflight")
    afl_apt = block.index("Install AFL++")
    cargo_afl = block.index("Install cargo-afl")
    assert pre < afl_apt < cargo_afl
    assert "fuzz_needed" in block
    assert "steps.fuzz_preflight.outputs.fuzz_needed == 'true'" in block


def test_check_job_runs_on_main_push_when_dco_jobs_skipped() -> None:
    block = _check_job_block()
    job_header = block.split("steps:")[0]
    assert "always() && !cancelled()" in job_header
    assert "(success() || failure())" not in job_header


def test_check_job_conditional_cargo_deny_install() -> None:
    block = _check_job_block()
    deny_version = _cargo_deny_version()
    assert f'CARGO_DENY_VERSION: "{deny_version}"' in block
    assert "Ensure cargo-deny" in block
    assert "id: cargo_deny" in block
    assert "steps.cargo_deny.outputs.present != 'true'" in block
    assert "cargo-deny@${{ env.CARGO_DENY_VERSION }}" in block
    ensure = block.index("Ensure cargo-deny")
    install = block.index("Install cargo-deny")
    diagnostics = block.index("Report CI cache diagnostics")
    assert ensure < install < diagnostics
    assert "CARGO_DENY_PRESENT" in block


def test_check_job_always_installs_llvm_cov_about_not_bundled_afl() -> None:
    block = _check_job_block()
    deny_version = _cargo_deny_version()
    assert "cargo-llvm-cov@0.8.5,cargo-about@0.9.0" in block
    install_tools = block.index("Install cargo tooling (llvm-cov, about)")
    install_afl = block.index("Install cargo-afl")
    assert install_tools < install_afl
    tools_section = block.split("Install cargo tooling")[1].split("Install cargo-afl")[0]
    assert "cargo-afl@0.18.0" not in tools_section
    assert f"cargo-deny@{deny_version}" not in tools_section.split("Install cargo-deny")[0]


def test_check_job_runs_via_run_check_script() -> None:
    block = _check_job_block()
    assert "./scripts/run-check.sh" in block
    assert "make -j check" not in block.split("Run make -j check")[1].split("\n")[2]


def test_super_linter_runs_on_main_push_when_dco_jobs_skipped() -> None:
    text = _CI.read_text(encoding="utf-8")
    start = text.index("  super-linter:")
    end = text.index("      - name: Run super-linter", start)
    header = text[start:end]
    assert "always() && !cancelled()" in header
    assert "(success() || failure())" not in header
