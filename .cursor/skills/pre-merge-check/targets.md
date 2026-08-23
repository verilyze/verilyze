<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Pre-merge target matrix

Run these targets only after code edits in the current session, or when the
user explicitly asks before commit/push. Do not run during Plan or Ask mode.
See [agent-workflow.mdc](../../rules/agent-workflow.mdc).

| Paths | Commands |
|-------|----------|
| `**/*.rs` (except `tests/fuzz/**`, `fuzz/**`) | `make fmt-check clippy`, `make cargo-test` (or scoped crate test); mem/Docker cache changes also `make cargo-test-mem` |
| `tests/fuzz/fuzz_targets/**`, `tests/fuzz/Cargo.toml`, `fuzz/fuzz_targets/**`, `fuzz/Cargo.toml`, `scripts/check_fuzz_target_parity.py` | `make check-fuzz-target-parity` (see [fuzz-harness-parity.mdc](../../rules/fuzz-harness-parity.mdc)) |
| `.clusterfuzzlite/**/*.sh` | `make lint-shell` |
| `Makefile` | `make test-scripts` (structural pytest under `tests/scripts/` asserts recipe shape; `check-fast` alone is not enough) |
| `scripts/**/*.py`, `tests/scripts/**` | `make lint-python test-scripts` |
| `scripts/**/*.sh` | `make lint-shell`; if the script is a Makefile check leaf that invokes tools, also `make test-scripts` covering quiet-by-default / `VLZ_CHECK_VERBOSE` stderr capture (see `tests/scripts/test_benchmark_gate.py`) |

| `architecture/**/*.mmd` | `make check-doc-diagrams` |
| config / `verilyze.conf.example` | `make check-config-docs` |
| `man/**` | `make check-manpages` |
| `packaging/**` | `make check-packaging` |
| Root `Cargo.toml`, `Cargo.lock`, `deny.toml` (not `fuzz/Cargo.toml`) | `make cargo-check-locked`, `make deny-check`, `make check-third-party-licenses`, `make check-sbom` |
| `pyproject.toml` | `make check-sbom`, `make check-pylock-dev` |
| `.github/workflows/**` (upload-sarif) | `make check-upload-sarif-example` |
| `.github/workflows/**`, `examples/**/*.yml` (action digest pins) | `make check-github-action-pin-comments` |
| `pylock.dev.toml` | `make check-pylock-dev` |
| `scripts/generate-pylock-dev.sh`, `scripts/check_pylock_dev.py`, `scripts/check-pylock-dev.sh` | `make check-pylock-dev`, `make lint-shell`, `make lint-python`, `make test-scripts` |
| New files | `make check-headers` |
| Super-linter paths | `make super-linter` (must exit 0 when touched) |
| Production behavior change | `make unit-tests`, `make check-pr` before PR |
| Non-behavior change before PR | `make check-fast` (includes `check-super-linter-native`) |
| Full CI | `make -j check` |

Super-linter paths: `.github/**`, `*.{yml,yaml}`, `biome.json`, `renovate.json`,
`.gitleaks.toml`, `.commitlintrc.json`, `scripts/super-linter.sh`,
`packaging/**/*.env`, `packaging/**/Dockerfile`.

Native parity (no Docker): `make check-super-linter-native` checks `obs-project.env`
key order, inline `checkov:skip=CKV_GHA_7` on `release.yml`, codespell, and
host gitleaks directory scan (`.gitleaks.toml`, `--redact`). Included in
`make check-fast`.

Incremental super-linter: `make super-linter`. Full tree (nightly parity):
`make super-linter-full`.
