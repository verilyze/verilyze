<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Guidance for AI agents and contributors

This file orients automated agents and human contributors to the key
sources of truth for the **super-duper (spd)** project.

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
    Per-trait plugin registries and `spd_register!` macro.
  - [architecture/workspace-layout.mmd](architecture/workspace-layout.mmd) --
    Workspace crates and trait definitions.

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
- Do not delete or modify the contents of the `COPYING` or `LICENSE` files at
  the root of the project.

## Quick links

| Topic            | Where to look                                  |
|------------------|------------------------------------------------|
| Exit codes       | PRD FR-009, FR-010, FR-016; README “Exit codes” |
| Config precedence| PRD CFG-001–CFG-008; README “Configuration precedence” |
| Adding a plugin  | CONTRIBUTING "Adding a new language plugin"; PRD MOD-002 |
| TDD workflow     | [CONTRIBUTING.md -- Test-driven development](CONTRIBUTING.md#test-driven-development-tdd) |
| Security         | PRD section 6 (SEC-*), section 11 (Risk & Threat Model); [SECURITY.md](SECURITY.md); [COMPLIANCE.md](COMPLIANCE.md) |
