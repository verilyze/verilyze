# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Main llvm-cov pass must compile crate-level language Tier D modules."""

from tests.scripts.repo_root import repo_root

_COVERAGE_SH = repo_root() / "scripts" / "coverage.sh"


def _main_llvm_cov_feature_block() -> str:
    """Return coverage.sh through the first cargo test --workspace invocation."""
    text = _COVERAGE_SH.read_text(encoding="utf-8")
    marker = "cargo test --workspace --exclude vlz-fuzz"
    idx = text.find(marker)
    assert idx != -1, "expected workspace cargo test in coverage.sh"
    return text[: idx + 400]


def test_main_llvm_cov_enables_go_and_rust_crate_tier_d() -> None:
    """vlz/rust-tier-d does not enable vlz-go/vlz-rust tests' own features."""
    block = _main_llvm_cov_feature_block()
    assert "vlz-go/tier-d" in block
    assert "vlz-rust/tier-d" in block
    assert "vlz/testing" in block
