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
| Super-linter paths | `make super-linter` (must exit 0 when touched) |
| Behavior change | `make unit-tests`, `make coverage-quick` before PR |
| Before PR | `make check-fast` (includes `check-super-linter-native`) |
| Full CI | `make -j check` |

Super-linter paths: `.github/**`, `*.{yml,yaml}`, `biome.json`, `renovate.json`,
`.gitleaks.toml`, `.commitlintrc.json`, `scripts/super-linter.sh`,
`packaging/**/*.env`, `packaging/**/Dockerfile`.

Native parity (no Docker): `make check-super-linter-native` checks `obs-project.env`
key order and inline `checkov:skip=CKV_GHA_7` on `release.yml`. Included in `make check-fast`.

Incremental super-linter: `make super-linter`. Full tree (nightly parity):
`make super-linter-full`.
