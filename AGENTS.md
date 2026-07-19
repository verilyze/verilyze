<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Guidance for AI agents and contributors

This file orients automated agents and human contributors to the key
sources of truth for the **verilyze (vlz)** project.

## Primary references

- **Requirements and scope:** [architecture/PRD.md](architecture/PRD.md)
  Functional (FR-*), non-functional (NFR-*), security (SEC-*), operational
  (OP-*), configuration (CFG-*), modularity (MOD-*), and documentation
  (DOC-*) requirements. Use requirement IDs when proposing or implementing
  features.

- **Contributing and crate layout:** [CONTRIBUTING.md](CONTRIBUTING.md)
  Crate architecture, public traits, extension points, how to add a new
  language plugin, code style, use of `write_stdout()` for CLI output, and
  **test-driven development (TDD)** workflow (preferred when adding or changing
  behavior).

- **Architecture diagrams (Mermaid):**
  - [architecture/execution-flow.mmd](architecture/execution-flow.mmd) -- Scan
    flow (config, find, parse, resolve, cache, report, exit codes).
  - [architecture/plugin-registration-flow.mmd](architecture/plugin-registration-flow.mmd) --
    Per-trait plugin registries and `vlz_register!` macro.
  - [architecture/workspace-layout.mmd](architecture/workspace-layout.mmd) --
    Workspace crates and trait definitions.

## AI agent requirements

When adding or changing **production logic** (Rust in `crates/**`, Python in
`scripts/` with branching, parsing, transformation, or I/O), you **must**
follow test-driven development (TDD):

1. **Write tests first** -- Define tests from expected inputs/outputs or behavior.
   Do not create mock implementations for functionality that does not exist yet.
2. **Run tests and confirm they fail** -- Ensure new tests fail for the right reason.
   Do not write implementation code at this stage.
3. **Implement to pass** -- Write the minimal code that makes the tests pass.
   Do not modify the tests to match the implementation.
4. **Iterate** -- Keep iterating on the implementation until all tests pass.
5. **Code coverage** -- Meet PRD minimum thresholds (NFR-012). For Python,
   each touched `scripts/**/*.py` module should reach **>= 95% line coverage**
   (target 100% where practical). Add mocking if necessary.

Full workflow and rationale:
[CONTRIBUTING.md -- Test-driven development](CONTRIBUTING.md#test-driven-development-tdd).
Test layering (what not to test):
[CONTRIBUTING.md -- Test scope and layering](CONTRIBUTING.md#test-scope-and-layering).

**TDD not required** for Makefile-only, `.github/**` workflow-only,
packaging-only, or documentation-only changes. Run the relevant `make check-*`
targets instead of adding `read_text()` substring tests on config files.

**Scope:** Mandatory TDD applies only to AI agents on production logic. Human
contributors may use TDD but it remains **preferred**, not required (see
CONTRIBUTING.md). Exceptions for AI: documentation-only, comment/typo fixes, or
changes that do not affect observable behavior.

## Pre-merge validation

Before commit, push, or opening a PR, run the minimal local gates for what
changed. Full path-to-target matrix:
[`.cursor/skills/pre-merge-check/targets.md`](.cursor/skills/pre-merge-check/targets.md).

1. After edits: path-scoped `make` targets from that matrix
2. Production behavior (`crates/**`, `scripts/**/*.py` logic): `make check-pr`
   before declaring PR-ready
3. Non-behavior docs/config-only work: `make check-fast` before declaring
   PR-ready
4. Super-linter paths touched: `make super-linter` must exit 0 (Docker)
5. Dependency manifests (`Cargo.toml`, `Cargo.lock`, `pyproject.toml`): targeted
   deny, locked Cargo check, license, and SBOM gates from the matrix
6. Human-only: signed commits + DCO (`make setup-hooks` recommended)

`make check-pr` runs `check-fast` then `coverage-quick` sequentially
(cache-dependent cost). Full CI parity: `make -j check`.

## Conventions

- **TDD:** Strict for production Rust and Python script logic; use make/lint
  gates for config and wiring. See
  [CONTRIBUTING.md -- Test scope and layering](CONTRIBUTING.md#test-scope-and-layering)
  and [Test-driven development](CONTRIBUTING.md#test-driven-development-tdd).
- **Commit bodies:** When a commit lists multiple distinct changes, use `-`
  bullets in the body (72-char wrap). Single-change bodies stay prose. See
  [CONTRIBUTING -- Commit messages](CONTRIBUTING.md#commit-messages).
- Follow SOLID and the Unix philosophy as stated in the PRD (design principles).
- The codebase uses `#![deny(unsafe_code)]`; no new `unsafe` or
  `#[allow(unsafe_code)]` without explicit justification and approval.
- When changing behavior or CLI, align with the PRD and update README,
  [INSTALL.md](INSTALL.md), or CONTRIBUTING if user- or contributor-facing.
- Do not delete or modify the root `LICENSE` file or any files in the
  `LICENSES` directory.
- **Dashes:** Do not use em dashes or en dashes in code comments or
  documentation. Use `--` instead of em dashes, and `-` instead of en dashes.
- **SPDX headers (manual):** When adding SPDX copyright/license headers without
  using REUSE (`make headers` or `reuse annotate`), include a trailing blank
  line after the header block. Use an actual blank line (empty), not a commented
  blank line (e.g. `# ` or `// `). This prevents REUSE automation from
  replacing existing file header comments when it later adds or updates SPDX
  tags.
- **No duplicate copyright holders:** Do not add the same copyright owner twice.
  Use `.mailmap` to map alternate identities (e.g. different emails) to a single
  canonical form. See CONTRIBUTING "Copyright and licensing".
- **DRY:** Avoid hard-coding values. Use constants (single `pub const` for shared
  values), configuration (for user-overridable values), or programmatic
  derivation. Tests must use the same constants as production. See PRD NFR-024,
  CONTRIBUTING "DRY (Don't Repeat Yourself)".
- **Python modern style:** Follow CONTRIBUTING Python style (3.11+ typing; no
  `__future__` imports or legacy `typing` aliases).

## Quick links

| Topic                | Where to look                                            |
|----------------------|----------------------------------------------------------|
| Install / build      | [INSTALL.md](INSTALL.md); README “Quick start”           |
| Exit codes           | PRD FR-009, FR-010, FR-016; README “Exit codes”          |
| Shell script style   | CONTRIBUTING "Code style and checks"; PRD NFR-022        |
| Config precedence    | PRD CFG-001--CFG-008; README “Configuration precedence”  |
| HTTP proxy (CVE)     | PRD OP-018; [INSTALL.md](INSTALL.md); `man vlz` ENVIRONMENT |
| CI script inputs (GHA) | PRD OP-019; CONTRIBUTING "GitHub Actions (`ci.yml`)"; [scripts/lib/ci-input-validate.sh](scripts/lib/ci-input-validate.sh) |
| Adding a plugin      | CONTRIBUTING "Adding a new language plugin"; PRD MOD-002 |
| Config documentation | CONTRIBUTING "Adding or updating configuration keys"; `make generate-config-example` |
| Commit messages      | CONTRIBUTING "Commit messages"                           |
| TDD / test scope     | [CONTRIBUTING.md -- Test scope and layering](CONTRIBUTING.md#test-scope-and-layering); [TDD](CONTRIBUTING.md#test-driven-development-tdd) |
| Pre-merge validation | This file "Pre-merge validation"; [targets.md](.cursor/skills/pre-merge-check/targets.md) |
| Security             | PRD section 6 (SEC-*), section 11 (Risk & Threat Model); [SECURITY.md](SECURITY.md); [COMPLIANCE.md](COMPLIANCE.md) |
| OpenSSF Best Practices | [bestpractices.dev](https://www.bestpractices.dev/en/projects/12361) |
| Copyright duplicates | `make check-header-duplicates`; CONTRIBUTING "Copyright and licensing"; `.mailmap` |
| DRY / constants      | PRD NFR-024; CONTRIBUTING "DRY (Don't Repeat Yourself)"                              |
| Parser selection     | PRD NFR-025 (manifest format compatibility, use existing vs in-house)               |
| Super-linter         | CONTRIBUTING "Code style and checks" (Super-linter bullet; Biome file globs in [biome.json](biome.json)) |
| Renovate             | [renovate.json](renovate.json); [`.github/workflows/renovate.yml`](.github/workflows/renovate.yml); GitHub App secrets `RENOVATE_APP_CLIENT_ID` / `RENOVATE_APP_PRIVATE_KEY`; Cargo workspace + `RENOVATE_ALLOWED_COMMANDS` (CONTRIBUTING Super-linter / Rust sections) |
