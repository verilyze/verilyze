# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract: CI check job caches, linker env, and lazy AFL preflight."""

from pathlib import Path

from tests.scripts.repo_root import repo_root

_CI = repo_root() / ".github" / "workflows" / "ci.yml"


def _check_job_block() -> str:
    text = _CI.read_text(encoding="utf-8")
    start = text.index("  check:")
    end = text.index("  coverage-pr-comment:", start)
    return text[start:end]


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


def test_check_job_always_installs_llvm_cov_deny_about_not_bundled_afl() -> None:
    block = _check_job_block()
    assert "cargo-llvm-cov@0.8.5,cargo-about@0.9.0" in block
    assert "cargo-deny@0.20.0" in block
    install_tools = block.index("Install cargo tooling (llvm-cov, deny, about)")
    install_afl = block.index("Install cargo-afl")
    assert install_tools < install_afl
    assert "cargo-afl@0.18.0" not in block.split("Install cargo tooling")[1].split(
        "Install cargo-afl"
    )[0]


def test_check_job_runs_via_run_check_script() -> None:
    block = _check_job_block()
    assert "./scripts/run-check.sh" in block
    assert "make -j check" not in block.split("Run make -j check")[1].split("\n")[2]
