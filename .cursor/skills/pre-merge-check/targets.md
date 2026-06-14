<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Pre-merge target matrix

| Paths | Commands |
|-------|----------|
| `**/*.rs` | `make fmt-check clippy`, `make cargo-test` (or scoped crate test) |
| `scripts/**/*.py`, `tests/scripts/**` | `make lint-python test-scripts` |
| `scripts/**/*.sh` | `make lint-shell` |
| `architecture/**/*.mmd` | `make check-doc-diagrams` |
| config / `verilyze.conf.example` | `make check-config-docs` |
| `man/**` | `make check-manpages` |
| `packaging/**` | `make check-packaging` |
| `Cargo.toml`, `deny.toml` | `make deny-check` (+ third-party licenses if deps changed) |
| New files | `make check-headers` |
| Super-linter paths | `make super-linter` |
| Behavior change | `make unit-tests`, `make coverage-quick` before PR |
| Before PR | `make check-fast` |
| Full CI | `make -j check` |

Super-linter paths: `.github/**`, `*.yml`, `*.yaml`, `biome.json`, `renovate.json`,
`.gitleaks.toml`, `.commitlintrc.json`, `scripts/super-linter.sh`.
