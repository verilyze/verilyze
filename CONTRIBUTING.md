# Contributing to super-duper

Thank you for your interest in contributing. This document gives a short
overview of the crate layout and extension points.

## Crate architecture

The workspace is split into:

- **spd** – Binary; parses CLI, loads config, dispatches subcommands, runs the
  scan pipeline.
- **spd-db** – Trait definitions: `Package`, `CveRecord`, `DatabaseBackend`,
  etc.
- **spd-db-redb** – Default RedB implementation for CVE cache and
  false-positive (ignore) DB.
- **spd-manifest-finder** – Trait `ManifestFinder`; default implementation
  finds Python manifest files (or regex from config).
- **spd-manifest-parser** – Traits `Parser` and `Resolver`; parses manifests
  into a dependency graph and resolves to packages.
- **spd-cve-client** – Trait `CveProvider`; default OSV.dev client.
- **spd-report** – Trait `Reporter`; plain, JSON, HTML, SARIF reporters.
- **spd-integrity** – Trait `IntegrityChecker`; default delegates to backend
  `verify_integrity`.
- **spd-plugin-macro** – `spd_register!` macro for registering default plugins
  in the binary.

The binary uses **per-trait registries** (e.g. `FINDERS`, `PARSERS`,
`RESOLVERS`, `PROVIDERS`, `DB_BACKENDS`, `REPORTERS`, `INTEGRITY_CHECKERS`) and
calls `ensure_default_*` at startup to push default implementations. Optional
backends (e.g. SQLite) can be added as separate crates and registered via Cargo
features.

## Adding a new language plugin

1. Create a new crate (e.g. `spd-java`) that implements:
   - `ManifestFinder` – discover manifest files (e.g. `pom.xml`).
   - `Parser` – parse manifest into `DependencyGraph`.
   - `Resolver` – resolve to `Vec<Package>` (e.g. using lock file or package
     manager).
2. Gate the crate behind a Cargo feature in the `spd` binary.
3. In the binary’s startup path, when the feature is enabled, register your
   implementations (e.g. push to the appropriate registry or use a registration
   macro).

See [architecture/PRD.md](architecture/PRD.md) MOD-002 and FR-020 for the
formal trait contracts.

## Code style and checks

- The codebase uses `#![deny(unsafe_code)]`.
- Run `cargo fmt` and `cargo clippy` before submitting.
- Add unit tests in the crate that owns the logic; integration tests where
  appropriate.

### CLI output (stdout)

In `spd/src/main.rs`, use the `write_stdout()` helper for all user-facing
stdout (e.g. anything that would otherwise be `println!`). Do not use
`println!` for that. This ensures every command exits with code 0 when stdout
is a broken pipe (e.g. `spd db show | less` then `q`), instead of panicking.
Stderr can stay as `eprintln!` or `log::error!`.

## Requirements

Full requirements (functional, non-functional, security, configuration) are in
[architecture/PRD.md](architecture/PRD.md). When adding features, align with
the relevant IDs (e.g. FR-*, NFR-*, SEC-*, CFG-*).
