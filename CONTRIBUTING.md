# Contributing to super-duper

Thank you for your interest in contributing. This document gives a short
overview of the crate layout and extension points.

## Crate architecture

The workspace is split into:

- **spd** -- Binary; parses CLI, loads config, dispatches subcommands, runs the
  scan pipeline.
- **spd-db** -- Trait definitions: `Package`, `CveRecord`, `DatabaseBackend`,
  etc.
- **spd-db-redb** -- Default RedB implementation for CVE cache and
  false-positive (ignore) DB.
- **spd-manifest-finder** -- Trait `ManifestFinder`; default implementation
  finds Python manifest files (or regex from config).
- **spd-manifest-parser** -- Traits `Parser` and `Resolver`; parses manifests
  into a dependency graph and resolves to packages.
- **spd-cve-client** -- Trait `CveProvider`; default OSV.dev client.
- **spd-report** -- Trait `Reporter`; plain, JSON, HTML, SARIF reporters.
- **spd-integrity** -- Trait `IntegrityChecker`; default delegates to backend
  `verify_integrity`.
- **spd-plugin-macro** -- `spd_register!` macro for registering default plugins
  in the binary.

The binary uses **per-trait registries** (e.g. `FINDERS`, `PARSERS`,
`RESOLVERS`, `PROVIDERS`, `DB_BACKENDS`, `REPORTERS`, `INTEGRITY_CHECKERS`) and
calls `ensure_default_*` at startup to push default implementations. Optional
backends (e.g. SQLite) can be added as separate crates and registered via Cargo
features.

## Adding a new language plugin

1. Create a new crate (e.g. `spd-java`) that implements:
   - `ManifestFinder` -- discover manifest files (e.g. `pom.xml`).
   - `Parser` -- parse manifest into `DependencyGraph`.
   - `Resolver` -- resolve to `Vec<Package>` (e.g. using lock file or package
     manager).
2. Gate the crate behind a Cargo feature in the `spd` binary.
3. In the binary’s startup path, when the feature is enabled, register your
   implementations (e.g. push to the appropriate registry or use a registration
   macro).

See [architecture/PRD.md](architecture/PRD.md) MOD-002 and FR-020 for the
formal trait contracts.

## Code style and checks

- Follow the [Rust Style Guide](https://doc.rust-lang.org/beta/style-guide/index.html).
- The codebase uses `#![deny(unsafe_code)]`.
- Run `cargo fmt` and `cargo clippy` before submitting.
- We **encourage** a **test-driven development (TDD)** approach (see below).
  Add unit tests in the crate that owns the logic; integration tests where
  appropriate. We may ask for tests to be added or updated before merging.
- Keep line lenghts to less than 100 characters. Give a best effort at keeping
  line lengths below 80 characters (i.e., 79 characters or less) so that users
  with 80-character terminals can view the entire line, even when viewing
  patch files/diffs. Some lines can extend past this guideline when it improves
  readability (e.g., long URLs that can't be reasonably broken apart).

### CLI output (stdout)

In `spd/src/main.rs`, use the `write_stdout()` helper for all user-facing
stdout (e.g. anything that would otherwise be `println!`). Do not use
`println!` for that. This ensures every command exits with code 0 when stdout
is a broken pipe (e.g. `spd db show | less` then `q`), instead of panicking.
Stderr can stay as `eprintln!` or `log::error!`.

## Running tests and coverage

- **Run tests:** `cargo test` runs the full suite. To test a single crate (see MOD-005): `cargo test -p <crate>` (e.g. `cargo test -p spd-cve-client`).
- **Generate coverage (cargo-llvm-cov, XML for CI):** Use **cargo-llvm-cov** with the **nightly** toolchain so all workspace crates appear in the report.
  1. Install cargo-llvm-cov: `cargo install cargo-llvm-cov --locked`
  2. Install the nightly toolchain and LLVM tools: `rustup toolchain install nightly` and `rustup component add llvm-tools --toolchain nightly`
  3. Run coverage from the repo root:
     - **Recommended:** `./scripts/coverage.sh` (or `make coverage`)
     - The script uses the [external tests](https://docs.rs/crate/cargo-llvm-cov/latest#get-coverage-of-external-tests) workflow: `cargo llvm-cov show-env`, then `cargo build` and direct binary invocation, so the xtask binary is covered without depending on `cargo llvm-cov run`.
     - Reports: `reports/index.html` (HTML), `reports/cobertura.xml` (CI)
     - Thresholds (NFR-012, NFR-017): >= 85% line, >= 80% function, >= 85% region, >= 70% branch (when stable). The coverage run **exits 1** when below threshold. Fail-under flags: `--fail-under-lines 85 --fail-under-functions 80 --fail-under-regions 85` (and `--fail-under-branch 70` when branch coverage is stable).
  **Note:** Branch coverage is currently **disabled** in the default coverage run (line, function, and region coverage only). Enabling `--branch` can trigger an LLVM llvm-cov crash (SIGSEGV) when the report includes the proc-macro crate. Until that toolchain bug is resolved, coverage reports show line, function, and region metrics; branch threshold (70%) remains the target when branch coverage is re-enabled.
- **CI:** The Cobertura XML (e.g. `reports/cobertura.xml`) is consumed by common CI systems; see [taiki-e/cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) or [taiki-e/install-action](https://github.com/taiki-e/install-action) for GitHub Actions.

## Test-driven development (TDD)

We use **test-driven development**: write tests that define the desired
behavior first, then implement code until those tests pass. TDD keeps
requirements explicit, avoids over-implementation, and gives a clear target for
each change. Tests belong in the crate that owns the logic (unit tests) or in
the appropriate integration test layout.

**Placement (Rust convention):** Unit tests live in the same file as the code
under test (or same crate) in a `#[cfg(test)] mod tests` block; integration
tests live in a top-level `tests/` directory or, for the binary, in tests that
run the built executable. **Documenting expected behavior:** Each test should
make the behavior it verifies clear—e.g. descriptive test names, a short `///`
doc comment tying the test to a requirement (e.g. FR-006, SEC-006), or
assertions that make the expected outcome obvious.

### TDD workflow

1. **Write tests** -- Define tests from expected inputs and outputs (or
   behavior). Be explicit that you are doing TDD so that agents do not create
   mock implementations for functionality that does not exist yet.
2. **Run tests and confirm they fail** – Run the test suite and ensure the new
   tests fail for the right reason. Do not write implementation code at this
   stage.
3. **Commit the tests** -- Once the tests are satisfactory, commit them.
4. **Implement to pass** -- Write the minimal code that makes the tests pass.
   Do not change the tests to match the implementation; iterate on the code
   until all tests pass.
5. **Commit the implementation** -- When all tests pass and you are satisfied,
   commit the implementation.

### Instructions for AI users

If you use an AI assistant to contribute, instruct your agent to follow the
following steps:

- **Step 1:** "Write tests based on expected input/output pairs. We are doing
  TDD--do not create mock implementations for functionality that does not exist
  yet."
- **Step 2:** "Run the tests and confirm they fail. Do not write implementation
  code at this stage."
- **Step 3:** Commit the tests when satisfied.
- **Step 4:** "Write code that passes the tests. Do not modify the tests. Keep
  iterating until all tests pass."
- **Step 5:** Commit the implementation when satisfied.

## Requirements

Full requirements (functional, non-functional, security, configuration) are in
[architecture/PRD.md](architecture/PRD.md). When adding features, align with
the relevant IDs (e.g. FR-*, NFR-*, SEC-*, CFG-*).
