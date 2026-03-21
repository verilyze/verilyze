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

When adding or changing behavior (new features, bug fixes, refactors that affect
behavior), you **must** follow test-driven development (TDD):

1. **Write tests first** -- Define tests from expected inputs/outputs or behavior.
   Do not create mock implementations for functionality that does not exist yet.
2. **Run tests and confirm they fail** -- Ensure new tests fail for the right reason.
   Do not write implementation code at this stage.
3. **Implement to pass** -- Write the minimal code that makes the tests pass.
   Do not modify the tests to match the implementation.
4. **Iterate** -- Keep iterating on the implementation until all tests pass.
5. **Code coverage** -- Ensure code coverage meets or exceeds the minimum
   thresholds defined in the PRD.md. Add mocking if necessary, and iterate
   until coverage thresholds are satisfied.

Full workflow and rationale:
[CONTRIBUTING.md -- Test-driven development](CONTRIBUTING.md#test-driven-development-tdd).

**Scope:** This requirement applies only to AI agents. Human contributors may use
TDD but it remains **preferred**, not required (see CONTRIBUTING.md). Exceptions
for AI: documentation-only, comment/typo fixes, or changes that do not affect
observable behavior.

## Conventions

- **TDD:** The project encourages test-driven development. When adding or
  changing behavior, prefer writing tests first, then implementation. See
  [CONTRIBUTING.md -- Test-driven development](CONTRIBUTING.md#test-driven-development-tdd)
  for the full workflow and AI-agent instructions.
- Follow SOLID and the Unix philosophy as stated in the PRD (design principles).
- The codebase uses `#![deny(unsafe_code)]`; no new `unsafe` or
  `#[allow(unsafe_code)]` without explicit justification and approval.
- When changing behavior or CLI, align with the PRD and update README or
  CONTRIBUTING if user- or contributor-facing.
- Do not delete or modify the files in the `LICENSES` directory.
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

## Quick links

| Topic                | Where to look                                            |
|----------------------|----------------------------------------------------------|
| Exit codes           | PRD FR-009, FR-010, FR-016; README “Exit codes”          |
| Shell script style   | CONTRIBUTING "Code style and checks"; PRD NFR-022        |
| Config precedence    | PRD CFG-001--CFG-008; README “Configuration precedence”  |
| Adding a plugin      | CONTRIBUTING "Adding a new language plugin"; PRD MOD-002 |
| Config documentation | CONTRIBUTING "Adding or updating configuration keys"; `make generate-config-example` |
| Commit messages      | CONTRIBUTING "Commit messages"                           |
| TDD workflow         | [CONTRIBUTING.md -- Test-driven development](CONTRIBUTING.md#test-driven-development-tdd) |
| Security             | PRD section 6 (SEC-*), section 11 (Risk & Threat Model); [SECURITY.md](SECURITY.md); [COMPLIANCE.md](COMPLIANCE.md) |
| Copyright duplicates | `make check-header-duplicates`; CONTRIBUTING "Copyright and licensing"; `.mailmap` |
| DRY / constants      | PRD NFR-024; CONTRIBUTING "DRY (Don't Repeat Yourself)"                              |
| Parser selection     | PRD NFR-025 (manifest format compatibility, use existing vs in-house)               |
| Super-linter         | CONTRIBUTING "Code style and checks" (Super-linter bullet); [biome.json](biome.json) |
