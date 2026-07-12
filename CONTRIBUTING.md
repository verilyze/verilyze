<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Contributing to verilyze

Thank you for your interest in contributing. This document gives a short
overview of the crate layout and extension points.

## Crate architecture

Crates are organized by plugin type under `crates/`:

- **crates/core/** -- Binary and trait-defining crates:
  - **vlz** -- Binary; parses CLI, loads config, dispatches subcommands, runs the
    scan pipeline.
  - **vlz-db** -- Trait definitions: `Package`, `CveRecord`, `DatabaseBackend`, etc.
  - **vlz-manifest-finder** -- Trait `ManifestFinder`; no default implementation.
  - **vlz-manifest-parser** -- Traits `Parser` and `Resolver`; defines
    `DependencyGraph`; no default implementations.
  - **vlz-cve-client** -- Trait `CveProvider` and `RawVulnDecoder`; defines the
    provider contract and decoder registry; includes default OSV.dev client.
  - **vlz-report** -- Trait `Reporter`; plain, JSON, HTML, SARIF, CycloneDX, SPDX
    reporters.
  - **vlz-integrity** -- Trait `IntegrityChecker`; default delegates to backend
    `verify_integrity`.
  - **vlz-plugin-macro** -- `vlz_register!` macro for registering default plugins
    in the binary.
- **crates/languages/** -- Language plugins (ManifestFinder, Parser, Resolver):
  - **vlz-python** -- Python: requirements.txt, pyproject.toml, Pipfile, setup.cfg, setup.py, etc.
  - **vlz-rust** -- Rust: Cargo.toml, Cargo.lock (workspace members supported).
- **crates/providers/** -- CVE providers (optional, feature-gated):
  - **vlz-cve-provider-nvd** -- NVD (NIST); `nvd` feature.
  - **vlz-cve-provider-github** -- GitHub Advisory Database; `github` feature.
  - **vlz-cve-provider-sonatype** -- Sonatype OSS Index; `sonatype` feature.
- **crates/db-backends/** -- Database backend implementations:
  - **vlz-db-redb** -- Default RedB implementation for CVE cache and
    false-positive (ignore) DB.

The binary uses **per-trait registries** (e.g. `FINDERS`, `PARSERS`,
`RESOLVERS`, `PROVIDERS`, `DB_BACKENDS`, `REPORTERS`, `INTEGRITY_CHECKERS`) and
calls `ensure_default_*` at startup to push default implementations. Language
support (e.g. `vlz-python`) and optional backends (e.g. SQLite) are gated
behind Cargo features; see **Feature gating** below.

See [execution-flow.mmd](architecture/execution-flow.mmd) for the full scan
pipeline.

```mermaid
graph TD
    %% Core binary
    A["vlz (binary crate)"]
    %% Macro crate (used by binary for plugin registration)
    M["vlz-plugin-macro"]
    %% Library crates
    B["vlz-manifest-finder"]
    C["vlz-manifest-parser"]
    D["vlz-cve-client"]
    E["vlz-db (trait definitions)"]
    F["vlz-report"]
    G["vlz-integrity"]
    %% Concrete implementations (plug‑ins)
    H["vlz-db-redb (default DatabaseBackend)"]
    I["vlz-db-sqlite (optional, future)"]
    J["vlz-db-mem (test/mock, future)"]
    %% Edges from binary to libraries
    A --> B
    A --> C
    A --> D
    A --> E
    A --> F
    A --> G
    A --> M
    %% Edges from libraries to the traits they expose (collapsed for brevity)
    B -.->|defines| ManifestFinder
    C -.->|defines| Parser
    D -.->|defines| CveProvider
    E -.->|defines| DatabaseBackend
    F -.->|defines| Reporter
    G -.->|defines| IntegrityChecker
    %% Registration edges (plug‑in discovery)
    H -->|"vlz_register! (feature = redb)"| A
    I -->|"vlz_register! (feature = sqlite)"| A
    J -->|"vlz_register! (feature = mem)"| A
    K["vlz-cve-provider-nvd"] -->|"vlz_register! (feature = nvd)"| A
```

## Quick setup

**Required system dependencies (install before `make setup`)**

| Dependency         | Purpose                                    | Install                      |
| ------------------ | ------------------------------------------ | ---------------------------- |
| Rust, Cargo        | Build and test                             | [rustup](https://rustup.rs/) |
| C toolchain/linker | Link Rust crates on build (GCC/clang)      | OS package manager           |
| Python 3 (≥3.11)   | Scripts, linters, tests                    | OS package manager           |
| ShellCheck         | Shell script linting                       | OS package manager           |
| GNU Make (4.0+)    | Build orchestration                        | OS package manager           |
| Git                | Contributing, hooks, fuzz change detection | OS package manager           |
| GnuPG 2.x/SSH key  | Commit signing (GPG or SSH; required)      | OS package manager           |

**Auto-installed by `make setup` (when missing)**

| Dependency               | Purpose                                | Installed by |
| ------------------------ | -------------------------------------- | ------------ |
| cargo-deny               | `make deny-check` / `make check`       | `make setup` |
| cargo-about              | `make check-third-party-licenses`      | `make setup` |
| cargo-llvm-cov           | Coverage (`make coverage*`)            | `make setup` |
| cargo-afl                | Fuzzing (`make fuzz*`)                 | `make setup` |
| pytest/pytest-cov        | Script tests (`make test-scripts`)     | `make setup` (`pyproject.toml` `[dev]`) |
| black/pylint/mypy/bandit | Python lint (`make lint-python`)       | `make setup` (`pyproject.toml` `[dev]`) |

**Recommended system dependencies**

| Dependency | Purpose                                | Install                                             |
| ---------- | -------------------------------------- | --------------------------------------------------- |
| AFL++      | Fuzzing (`make fuzz`, `make coverage`) | [AFL++](https://github.com/AFLplusplus/AFLplusplus) |

**Preferred linker policy**

- Default linker profile for this project: **gcc + GNU ld (`ld.bfd`)**.
- The Makefile sets default env values (`CC`, `RUSTFLAGS`) with `?=`,
  so users can override per command:
  - `CC=clang RUSTFLAGS="-Clink-arg=-fuse-ld=lld" make debug`
  - `CC=clang make check-fast`
- Coverage fallback remains available: `VLZ_COVERAGE_USE_BFD=1` enforces
  `-fuse-ld=bfd` for coverage runs (see [Running tests and coverage](#running-tests-and-coverage)).
- Typical first-time installs:
  - Debian/Ubuntu: `sudo apt install build-essential gcc binutils`
  - Fedora: `sudo dnf install gcc binutils`
  - openSUSE: `sudo zypper install gcc binutils`

After installing dependencies and cloning, run:

```sh
make setup
make -j check
```

End-user install options (release binary, `make install`, packages, Docker):
see [INSTALL.md](INSTALL.md).

Run `make` or `make help` for a full list of targets. `make setup` checks
system prerequisites (`python3`, `cargo`, `shellcheck`) and bootstraps
non-system developer tools (cargo-deny, cargo-about, cargo-llvm-cov,
cargo-afl, Python lint/test venvs). REUSE is auto-installed when
`check-headers` runs. Recommended: `make setup-hooks` for git hooks (REUSE
headers, DCO signoff, signature verification on push). Commit signing (GPG or
SSH) must be configured separately -- see
[Commit signing setup](#commit-signing-setup). For fuzz, AFL++ must be
installed separately. For coverage, use stable Rust with
`rustup component add llvm-tools` (CI installs this on stable).

### Quick reference

| Workflow              | Target                                             |
|-----------------------|----------------------------------------------------|
| List all targets      | `make` / `make help`                               |
| Bootstrap environment | `make setup`                                       |
| Full CI check         | `make check` (use `make -j check` for faster runs) |
| Quick build           | `make debug`                                       |
| Release build         | `make release` (stripped binary, NFR-023)          |
| Run tests             | `make unit-tests`                                  |
| Format Rust code      | `make fmt`                                         |
| Verify Rust format    | `make fmt-check`                                   |
| Run Clippy lints      | `make clippy`                                      |
| Dependency policy     | `make deny-check` (`cargo deny check`)             |
| Coverage (with fuzz)  | `make coverage`                                    |
| Coverage (skip fuzz)  | `make coverage-quick`                              |
| Fuzz smoke test       | `make fuzz`                                        |
| Fuzz changed only     | `make fuzz-changed`                                |
| Fuzz extended         | `make fuzz-extended`                               |
| Check DCO signoff     | `make check-dco`                                   |
| Check signatures      | `make check-signatures`                            |

## Branching and merging

We use trunk-based development with short-lived feature branches and rebased
branches. `main` is always buildable, tested, and releasable.

**Workflow:**

1. Create a branch from `main`:
   `git checkout main && git pull && git checkout -b feature/xyz` (or
   `fix/description` for bug fixes).
2. Work and commit. Keep branches short-lived and focused.
3. Before opening or updating a PR, rebase onto `main`:
   `git fetch origin main && git rebase origin/main`
4. Push: `git push --force-with-lease` (required after rebase).
5. Merge via GitHub's "Create a merge commit" button. All PRs must be
   rebased onto `main` before merging so the merge commit introduces no
   divergence.

We use merge commits instead of rebase-merge or squash-merge because GitHub's
rebase-merge [strips GPG signatures](https://github.com/orgs/community/discussions/11639)
from commits (leaving them unsigned), and squash-merge replaces them with
GitHub's own signature. Merge commits preserve the original signed commits.
Use `git log --first-parent` for a linear view of `main`.

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/). Format:

- **Subject:** `<type>[optional scope]: <description>` (e.g.
  `fix(parser): handle empty manifest`, `docs: add commit conventions`).
- **Subject line length:** 50 characters or less.
- **Body:** Optional for trivial changes, but required for any non-trivial
  changes. When adding a body, wrap lines at 72 characters.
- **Itemized bodies:** When the body lists two or more distinct changes, use
  `-` bullets (one change per line). A single cohesive change may use one prose
  paragraph instead. Wrap each bullet at 72 characters; continuation lines
  indent two spaces (standard Git wrap). A short summary paragraph before the
  list is fine when it frames the bullets. Leave a blank line between the
  body or list and `Signed-off-by:`.

  Multi-item example:

  ```
  feat: include orphan lock files in scan

  - Instead of reporting 0 manifest files found, when a lock file exists
    on its own, scan the lock file
  - When multiple lock files exist in the same directory (edge case),
    scan all of them and print a warning for this unexpected use case

  Signed-off-by: ...
  ```

  Summary paragraph plus bullets:

  ```
  fix(ci): add native codespell gate

  Catch spelling issues locally before PR via check-super-linter-native.

  - Rename the typing_extensions import alias to typing_ext in tests
  - Add scripts/check_codespell.py with .codespellrc parity
  - Wire codespell into check-super-linter-native and dev deps

  Signed-off-by: ...
  ```

- **DCO signoff:** All commits must include a `Signed-off-by` line attesting
  to the [Developer Certificate of Origin](https://developercertificate.org/).
  Use `git commit -s` to add it automatically. CI will reject PRs whose commits
  lack a valid signoff.
- **Commit signing (required):** All commits must be cryptographically
  signed (GPG or SSH). Use `git config commit.gpgsign true` to enable
  automatic signing. This is why squash and rebase merges are disabled --
  both strip contributor signatures. See [Commit signing setup](#commit-signing-setup)
  below for step-by-step instructions.

**Branch protection (GitHub):** Configure branch protection for `main` to
require PR reviews, passing CI, require signed commits, and disallow
force-push to `main`. Under Settings > General > Pull Requests, enable only
"Allow merge commits" and disable "Allow squash merging" and "Allow rebase
merging" so that the only available merge method preserves signatures.

**Super-linter / commitlint:** [`.commitlintrc.json`](.commitlintrc.json) extends
`@commitlint/config-conventional` (bundled in the super-linter image). With
`defaultIgnores: true`, merge commits such as GitHub’s `Merge pull request …`
and `Merge branch …` are skipped so only normal commits are checked against
Conventional Commits. Subject length in commitlint follows the conventional
preset (stricter than the 50-character guideline above); the 50-character rule
remains the project convention for authors.

### Commit signing setup

All commits must be signed. Git supports two signing backends; both are
equally accepted by the project's checks (`make check-signatures`, the
pre-push hook, and CI). Choose whichever suits your workflow.

**Option A: GPG signing**

1. Generate a key (ed25519 recommended, or RSA 4096):

   ```sh
   gpg --full-generate-key
   ```

2. Find your key ID:

   ```sh
   gpg --list-secret-keys --keyid-format=long
   ```

   Look for the long hex ID after `sec ed25519/` (or `sec rsa4096/`).

3. Configure Git:

   ```sh
   git config user.signingkey <KEY_ID>
   git config commit.gpgsign true
   git config tag.gpgsign true
   ```

4. Upload your public key to GitHub:

   ```sh
   gpg --armor --export <KEY_ID>
   ```

   Paste the output at GitHub > Settings > SSH and GPG keys > New GPG key.

5. If you use SSH sessions or a headless environment, add to your shell
   profile (e.g. `~/.bashrc`):

   ```sh
   export GPG_TTY=$(tty)
   ```

**Option B: SSH signing (Git 2.34+)**

1. Use an existing SSH key or generate one:

   ```sh
   ssh-keygen -t ed25519
   ```

2. Configure Git:

   ```sh
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519.pub
   git config commit.gpgsign true
   git config tag.gpgsign true
   ```

3. Upload the public key to GitHub > Settings > SSH and GPG keys. Add it
   as a **Signing key** (not just Authentication key).

4. For local strict verification (`make check-signatures`) to validate
   your own signatures, create an allowed signers file:

   ```sh
   echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" \
       >> ~/.ssh/allowed_signers
   git config gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
   ```

**Verify your setup:** After committing, run `make check-signatures` to
confirm your commits pass strict signature validation. The pre-push hook
(installed via `make setup-hooks`) also runs this check automatically before
each push.

For full details, see
[GitHub's guide to signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification).

## Versioning and releases

We use [Semantic Versioning](https://semver.org/) (SemVer). All crates
share a single workspace version defined in the root `Cargo.toml` under
`[workspace.package]` (see PRD MOD-007). Individual crates inherit it
with `version.workspace = true`.

**Pre-1.0 (0.x.y):** MINOR = new features (e.g. new plugin, new reporter);
PATCH = bug fixes, documentation.

**1.0.0 onward:** Standard SemVer (breaking = MAJOR, new feature = MINOR,
fix = PATCH).

**Release checklist:**

Release builds (`make release` or `cargo build --release`) produce binaries
stripped of symbols (NFR-023) for security and smaller size.

1. Update [CHANGELOG.md](CHANGELOG.md): add a curated `## [X.Y.Z]` section
   matching the new tag (without `v`). The Release workflow uses
   [scripts/extract-changelog-for-release.sh](scripts/extract-changelog-for-release.sh)
   to populate the GitHub Release body; it **fails** if that section is
   missing (OpenSSF Best Practices `release_notes`).
2. Bump `version` in the root `Cargo.toml` `[workspace.package]` section
   per SemVer.
3. Run `make generate-packaging` to update APKBUILD and PKGBUILD with the
   new version.
4. Merge to `main` and run `make check`.
5. Create signed annotated tag: `git tag -s v0.1.0 -m "Release v0.1.0"`.
6. Push tag: `git push origin v0.1.0`.
7. Confirm OBS release automation succeeds:
   - `release.yml` runs OBS signing-key checks in the preflight job (before
     builds), then builds assets, creates a **draft** GitHub Release, verifies
     checksums and Sigstore bundles locally and again after downloading the
     draft assets, and only then publishes the release (making it immutable if
     your repository uses immutable releases). OBS source upload and rebuild
     run in parallel once the tag preflight passes (upload-driven; no OBS
     source services on build.opensuse.org).
   - Ensure repository secrets `OBS_USER`, `OBS_PASSWORD`, and
     `OBS_TOKEN_REBUILD` are set for upload-driven OBS publishing
     (`osc` upload plus rebuild trigger):
     `osc token --create --operation rebuild <OBS_PROJECT> <OBS_PACKAGE>`.
   - Ensure `packaging/obs/obs-project.env` points at the intended OBS target.
   - When adding or removing OBS build targets, edit
     `packaging/obs/project/_meta` in git; the release workflow pushes it to
     OBS with `scripts/sync-obs-project-meta.sh --push` before source upload.
   - Run `make check-obs-packaging` and confirm OBS signing key metadata is
     present for the configured OBS project.
   - OBS upload automation also renders `verilyze.changes` from the same
     `CHANGELOG.md` section as the GitHub Release body (no extra manual step
     beyond updating `CHANGELOG.md`).

### Failed release before publish

If `release.yml` fails **before** the GitHub Release is published
(`gh release edit --draft=false` never ran), stabilize on **one** version and
**one** tag name. Do not bump the patch version for each CI fix attempt.

1. Fix on the release branch with ordinary commits (keep `Cargo.toml` at `X.Y.Z`).
2. Add bullets under the existing `## [X.Y.Z]` section in `CHANGELOG.md`.
3. Choose recovery by failure type:

| Situation | Action |
|-----------|--------|
| Transient (network, rate limit, secret fixed in GitHub UI) | Re-run failed jobs on the same tag/commit |
| Code or workflow script fix | Move the tag to the fix commit and push again (see below) |
| Draft GitHub Release exists with broken assets | `gh release delete vX.Y.Z --yes`, then move tag or re-run |

**Move tag and retry** (same version):

```sh
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
git tag -s vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

Re-pushing the tag triggers a new `release.yml` run on the updated commit.

**After publish:** If the release was already published, do **not** move the
tag. Cut the next patch version (`X.Y.(Z+1)`) instead.

**Optional:** Trigger `release.yml` via **workflow_dispatch** from a branch ref
to exercise build and OBS jobs without pushing a tag. Tag push remains the
canonical publish for SemVer artifacts and GitHub Releases.

**Verify locally (optional):** `./scripts/extract-changelog-for-release.sh X.Y.Z > /tmp/notes.md`
   The argument must be **SemVer without a `v` prefix** (Cargo-style, aligned
   with `[workspace.package].version`); invalid strings exit **2** (PRD OP-019).

## Adding a new language plugin

To add support for a new language (e.g., Java), you implement three traits
(`ManifestFinder`, `Parser`, `Resolver`), register them via a macro, and gate
the crate behind a Cargo feature. Before implementing a parser, check whether
the manifest format is compatible with an existing parser (e.g. TOML, JSON);
see PRD NFR-025 for parser selection guidance. Formal trait contracts (method signatures,
error types) are in [architecture/PRD.md](architecture/PRD.md) MOD-002 and
FR-020. The diagrams below illustrate the model.

**Registration flow** -- Plugins register at compile time; the binary discovers
them at startup:

```mermaid
sequenceDiagram
    participant Core as vlz "(core binary)"
    participant Registries as "per-trait OnceLock registries"
    participant Plugin as "language / provider crate"

    note over Registries: One Vec per trait: FINDERS, PARSERS,<br/>RESOLVERS, PROVIDERS, DB_BACKENDS,<br/>REPORTERS, INTEGRITY_CHECKERS

    %% Plug‑in registration (compile-time, one-way)
    Plugin -) Registries: vlz_register!(Trait, Impl)  // pushes Box::new(Impl) to the matching registry

    %% Runtime start‑up (core reads the compiled registries)
    Core ->> Registries: ensure_default_*() / enumerate plug‑ins
    Registries -->> Core: ManifestFinder instances
    Registries -->> Core: Parser instances
    Registries -->> Core: Resolver instances
    Registries -->> Core: CveProvider instances
    Registries -->> Core: DatabaseBackend instances
    Registries -->> Core: IntegrityChecker instances
    Registries -->> Core: Reporter instances
```

**Data pipeline** -- Your `ManifestFinder`, `Parser`, and `Resolver`
implementations participate in this data pipeline. See
[execution-flow.mmd](architecture/execution-flow.mmd) for where this pipeline
fits in the full scan.

```mermaid
flowchart LR
    Root[Scan root] --> Finder[ManifestFinder::find]
    Finder --> Manifests[Manifest paths]
    Manifests --> Parser[Parser::parse]
    Parser --> DepGraph[DependencyGraph]
    DepGraph --> Resolver[Resolver::resolve]
    Resolver --> Packages[Vec Package]
    Packages --> CVE[CVE lookup]
```

### Reachability tiers (maintainer reference)

Use the same tier names in code comments, docs, and tests:

- **Tier A** -- No source analysis. `reachable` is unknown.
- **Tier B** -- Consumer-project import/reference analysis against package identity.
  Emit `true` only for unambiguous positive evidence, `false` only for
  confident absence, otherwise unknown.
- **Tier C** -- Tier B plus advisory symbol/path metadata for CVE-specific matching.
- **Tier D** -- Tier C plus deeper dependency source and flow analysis.

Tier B must not imply Tier C or Tier D precision. When in doubt, prefer
unknown over false.

Runtime selection currently supports `off`, `tier-b`, and
`best-available` via config `reachability_mode`, env
`VLZ_REACHABILITY_MODE`, or CLI `--reachability-mode`.
`best-available` applies Tier C (advisory symbol/path metadata) where the
language analyzer supports it, and Tier B otherwise. Python Tier D (AST name-node
refinement) is available only when the `python-tier-d` feature is enabled at
build time; it refines unknown Tier C results and never downgrades Tier C
reachable decisions.

Set `VLZ_REACHABILITY_PERSIST_CACHE=1` (or `true`/`yes`) to persist Tier B and
per-CVE Tier C decisions under `.vlz/reachability-cache.json` in the scan root.

### Reachability analyzer plugin

Tier B language logic is pluginized. Language crates implement
`ReachabilityAnalyzer` from
`crates/core/vlz-reachability-trait/src/lib.rs` and register defaults in
core startup, similar to finder/parser/resolver registration.

1. Create a new crate under `crates/languages/` (e.g.
   `crates/languages/vlz-java/`) that implements:
   - `ManifestFinder` -- discover manifest files (e.g. `pom.xml`).
   - `Parser` -- parse manifest into `DependencyGraph`.
   - `Resolver` -- resolve to `Vec<Package>` (e.g. using lock file or package
     manager).
   - `ReachabilityAnalyzer` -- Tier B package reachability decision for this
     language.
2. Gate the crate behind a Cargo feature in the `vlz` binary: add your crate
   (e.g. `vlz-java`) as an optional dependency and define a feature (e.g.
   `java`) that enables it. When the feature is enabled, your crate is compiled
   and its `vlz_register!` calls run (see Registration flow above). For feature
   mechanics and examples, see **Feature gating** below.
3. In the binary’s startup path, when the feature is enabled, register your
   implementations via `vlz_register!` (or push to the registry directly).
4. **Add a fuzz target** for each manifest or lock format your parser supports
   (NFR-020, SEC-017). Parsers accept untrusted manifest files; fuzzing ensures
   no crash on malformed input (SEC-017). Create
   `tests/fuzz/fuzz_targets/<format>.rs` (e.g. `fuzz_pyproject_toml.rs`) and
   add seed corpus under `tests/fuzz/corpus/<format>/`. Update
   `scripts/fuzz-targets.map` (add one mapping line:
   `target_name=crates/languages/vlz-java/src/...`), `scripts/fuzz.sh`, and
   `tests/fuzz/Cargo.toml` to include the new target.

See [architecture/PRD.md](architecture/PRD.md) MOD-002 and FR-020 for the
formal trait contracts.

### Adding a new CVE provider

Per MOD-001 and MOD-002, optional CVE providers live in **separate crates**
(e.g. `vlz-cve-provider-nvd`). The default OSV provider remains in
`vlz-cve-client`; additional providers use their own crates.

1. Create a new crate under `crates/providers/` (e.g.
   `crates/providers/vlz-cve-provider-nvd/`) that:
   - Depends on `vlz-cve-client` (trait `CveProvider`, types `FetchedCves`,
     `ProviderError`) and `vlz-db` (`Package`, `CveRecord`).
   - Implements `CveProvider` (including `name()` for provider selection).
   - Implements `RawVulnDecoder` (or provides a decoder) and registers it
     with `vlz_cve_client::register_decoder()` so the cache can decode your
     provider's raw JSON back to `CveRecord`s.
2. Gate the crate behind a Cargo feature in the `vlz` binary (e.g. `nvd`).
   When the feature is enabled, your crate is compiled and registers its
   provider and decoder at startup.
3. In the binary's startup path (e.g. `ensure_default_cve_provider`), when
   the feature is enabled, register your provider via `vlz_register!` or push
   to the PROVIDERS registry.

**Important:** Map retryable errors (connection timeout, connection refused,
rate limiting 429, server errors 5xx) to `ProviderError::Network` or
`ProviderError::Transient` so that `RetryingCveProvider` automatically
applies exponential backoff (NFR-005, SEC-007). Use
`Transient { retry_after_secs: Some(n), ... }` when the upstream API returns
a Retry-After value (e.g. HTTP 429 with header).

**Provider-specific notes:** NVD uses CPE for package lookup; map PyPI
packages to `cpe:2.3:a:{package}:{package}:{version}:*:*:*:*:python:*:*`
(package name as vendor; NVD's cpeName rejects wildcard vendor). NVD
unauthenticated rate limit is 5 req/30s. Future multi-provider scans
(`--providers osv,nvd` or `--providers all`) are planned as a roadmap
enhancement; the cache design supports this.

**Auth and credential redaction:** Providers that accept credentials (e.g.
GitHub via `GITHUB_TOKEN`/`VLZ_GITHUB_TOKEN`, Sonatype via
`VLZ_SONATYPE_EMAIL`+`VLZ_SONATYPE_TOKEN`) must read from environment
variables only; never store or log credentials. Error messages and
`ProviderError::Display` must never contain token values or email addresses
(SEC-020). Add tests that assert error output does not contain credential
strings (e.g. `assert!(!format!("{}", err).contains("secret"))`).

## Adding or updating configuration keys

Config docs are generated from a single source. When adding or changing a
config key:

**Source of truth:** `crates/core/vlz/src/config.rs` and
`crates/core/vlz-report/src/lib.rs` define defaults.
`vlz config --list` prints the canonical table.

**Workflow:**

1. Add the key to `config.rs` (and ensure `vlz config --list` includes it).
2. Add an entry to `scripts/config-comments.toml` with `description`, `type`,
   `env`, `cli`, and `default` (if not in `config --list`).
3. Run `make generate-config-example` to regenerate `verilyze.conf.example`,
   `docs/configuration.md`, `man/verilyze.conf.5`.
4. When changing the CLI (subcommands, options), run `make generate-completions`
   to regenerate shell completions (bash, zsh, fish) in `completions/`.
5. When changing the CLI (subcommands, options), run `make generate-manpages`
   to regenerate `man/vlz.1` used by `vlz help`. The generated manpage SPDX
   header values come from `pyproject.toml` `[tool.vlz-headers]` (`default_*`).
6. Commit the generated files.

**Verification:** `make check-config-docs` (runs
`generate_config_example.py --check`) fails if outputs are out of sync.
CI runs this as part of `make check`.

**Files:** `scripts/config-comments.toml`, `docs/configuration.md.in`, and
`man/verilyze.conf.5.in` are templates; the script fills placeholders from
config data and `vlz config --list` output.

**Future migration:** If config keys grow significantly, consider extracting a
`vlz-config` crate to centralize schema, env vars, and CLI flags (see
architecture/PRD.md DOC-003 and design notes on single source of truth).

## Feature gating (MOD-003)

The `vlz` binary supports optional capabilities via Cargo features:

- **runtime** = `["redb", "python", "rust", "go"]` -- single source of truth for scan
  capabilities. When adding a new language or default backend, add it here so
  both default and Docker builds pick it up automatically.
- **default** = `["runtime", "completions", "docs"]` -- full build with runtime
  capabilities plus shell completion generation and man page via `vlz help`.
  Release builds omit the `testing` feature for a smaller binary.
- **completions** -- `vlz generate-completions` subcommand (bash, zsh, fish);
  pulls in `clap_complete`. Omitted from Docker image to reduce binary size.
- **docs** -- Man page via **`vlz help`** (runs `man` on embedded `vlz.1`); optional
  `vlz help [SUBCOMMAND]` is accepted and currently shows the same manual (MOD-009,
  DOC-013). When omitted, `vlz help` exits 2 with a message to rebuild or find
  docs online. Omitted in minimal build for smaller binary.
- **docker** = `["runtime"]` -- runtime only, no completions. Use for the Docker
  image (OP-013, FR-025). The Dockerfile uses `--no-default-features
  --features docker`; when adding new languages or backends, update only
  `runtime` in Cargo.toml, not the Dockerfile.
- **redb** -- RedB database backend for CVE cache and false-positive DB.
- **python** -- Python language plugin (`vlz-python` crate).
- **rust** -- Rust language plugin (`vlz-rust` crate).
- **nvd** -- NVD CVE provider (`vlz-cve-provider-nvd` crate); opt-in.
- **github** -- GitHub Advisory CVE provider (`vlz-cve-provider-github` crate);
  opt-in.
- **sonatype** -- Sonatype OSS Index CVE provider (`vlz-cve-provider-sonatype`
  crate); opt-in.
- **testing** -- Mocks and registry clear helpers for integration tests. Opt-in;
  use `--features vlz/testing` when running `cargo test` directly. `make
  unit-tests` and `make coverage` enable it automatically.
- **perf-instrumentation** -- Compile-time gate for performance counters and
  instrumentation logs (for example Tier-B reachability counters). Opt-in;
  not included in standard default or release builds.
- **sqlite**, **mem** -- placeholders for future backends.

NVD is opt-in because: (1) NVD enforces 5 requests per 30-second window for
unauthenticated use, whereas vlz defaults to 10 parallel queries, so a
cold-cache scan would immediately hit rate limits; (2) including NVD increases
binary size and dependencies (PRD Purpose & Scope, NFR-019, MOD-004); (3) PRD
MOD-003 specifies OSV-only as the default CVE provider.

Build a **minimal binary** (no Python, no Rust, no RedB) with:

```sh
cargo build --no-default-features
```

Build with only Rust (no Python):

```sh
cargo build --no-default-features --features rust
```

Build with only Java (when `vlz-java` exists) and no Python/Rust:

```sh
cargo build --no-default-features --features java
```

Build for **Docker** (runtime only, no completions; smaller image):

```sh
cargo build --release --no-default-features --features docker
```

`make docker` sends the repository root as the build context. The root
`.dockerignore` excludes `target/`, `.git/`, and other local artifacts so the
context stays small (large contexts can fail or slow the build). The scratch
image runs as UID 1000 and ships a writable `/home/verilyze` so default XDG-style
cache and data paths work without running as root.

Build with NVD CVE provider in addition to defaults:

```sh
cargo build --features nvd
```

Build with GitHub and Sonatype CVE providers:

```sh
cargo build --features github,sonatype
```

Build with performance instrumentation enabled:

```sh
cargo build --features perf-instrumentation
```

A minimal build omits language plugins, the RedB backend, and man page
documentation; `vlz list` will output nothing, `vlz scan` will fail with "No
ManifestFinder plug‑in registered", and `vlz help` will exit 2 with a message
to rebuild with docs or find documentation online. See [architecture/PRD.md]
(architecture/PRD.md) MOD-003, MOD-009.

## Adding dependencies

Before adding a dependency, consider whether the functionality can be
implemented in-house. If the logic is simple (e.g., string splitting, basic
parsing, small helpers), implement it in the relevant crate. If a dependency
is necessary, document in the PR: (a) why in-house is not practical, (b)
GPL-3.0 compatibility, (c) impact on `cargo tree` / build time. See
[architecture/PRD.md](architecture/PRD.md) NFR-019, MOD-004, and the Minimal
Dependencies design principle.

- When using regex on untrusted patterns or input, satisfy SEC-022 (no
  catastrophic backtracking).

### Duplicate package triage (`cargo-deny` bans)

Use this workflow when `make deny-check` reports duplicate crates:

1. Run `make deny-check` and inspect duplicate warnings.
2. Run `cargo tree -d` to identify which dependency paths introduce each
   duplicate.
3. Prefer unifying versions through `[workspace.dependencies]` in the root
   `Cargo.toml`, then consume those versions with `*.workspace = true` in crate
   manifests.
4. If duplicates are target- or ecosystem-constrained and cannot be unified,
   add narrowly scoped `bans.skip` entries in `deny.toml` with a clear `reason`.
   Prefer crate+version entries over broad `skip-tree`.
5. Keep duplicate policy strict by default (`multiple-versions = "deny"`), and
   use justified, minimal exceptions only.
6. Re-audit existing `bans.skip` entries periodically by removing one skip at a
   time in a temporary deny config and running `cargo deny check bans`. Remove
   skip entries immediately when they no longer trigger duplicate failures.
7. For any dependency version or feature change made during convergence, run
   `cargo deny check licenses` (or `make deny-check`) and keep only
   GPL-3.0-or-later-compatible results.

Current audit outcome for verilyze:
- Skips in `deny.toml` are still required today. Removing any current skipped
  crate causes `cargo deny check bans` duplicate failures.
- Remaining skips are platform-conditional runtime transitive dependencies
  (macOS/Windows) or upstream major-version constraints in the rustls/ring
  ecosystem. They are not primarily fuzz-only dependencies.

## Copyright and licensing (REUSE)

The project uses the [REUSE](https://reuse.software/) toolchain for SPDX
copyright and license headers. Default license and copyright are defined in
`pyproject.toml` under `[tool.vlz-headers]`.

- **Third-party licenses:** See [docs/LICENSING.md](docs/LICENSING.md) for
  licenses vs components, sync workflow, and check targets. THIRD-PARTY-LICENSES
  is committed; run `make generate-third-party-licenses` when dependencies
  change (requires `cargo install cargo-about`). `make sync-license-config`
  copies deny.toml [licenses] allow to about.toml; it runs automatically
  before license generation. `make check-third-party-licenses` verifies the
  committed file is up to date.
- **Workspace SBOM (SEC-019):** Committed CycloneDX/SPDX files under `sbom/v1/`
  from `make generate-sbom` (dogfoods `vlz scan`). `make check-sbom` verifies
  they match a fresh scan. CI: `.github/workflows/supply-chain.yml`.
- **JSON report schema (DOC-005):** [schemas/v1/report.json](schemas/v1/report.json);
  `make check-report-schema` validates schema and live output.
- **CI scan example (NFR-014):** [examples/github-action-vlz-scan.yml](examples/github-action-vlz-scan.yml).
- **Check headers:** `make check-headers` (runs `check-header-duplicates` and
  `reuse lint`)
- **Add/update headers:** `make headers` (runs `scripts/update_headers.py`).
  Files matched by a `path` in `REUSE.toml` under `[[annotations]]` are not
  passed to `reuse annotate`, consistent with `reuse lint` (license for those
  paths is declared only in `REUSE.toml`).
- **Protected files:** The root `LICENSE` file must not be modified. The
  pre-commit hook rejects staged changes to `LICENSE`. Optional: `chmod 444
  LICENSE` blocks accidental shell edits; use `chmod 644` before a rare
  intentional update.
- **Install Git hooks:** Run `make setup-hooks` or `./scripts/install-hooks.sh`
  to add pre-commit (REUSE headers), commit-msg (DCO signoff), and pre-push
  (commit signature verification) hooks. The pre-commit hook inserts headers
  using the Git author as the copyright holder. The pre-push hook runs
  `check-signatures.sh` in strict mode before each push. Requires
  `git config user.name` and `user.email` to be set.
- **Manual SPDX headers:** If you add SPDX headers by hand (e.g. when creating
  a new file before running `make headers`), include a trailing blank line after
  the header block. Use an actual empty line, not a commented blank line. This
  ensures REUSE automation does not overwrite or merge incorrectly with
  existing header content when `reuse annotate` or `make headers` runs later.

REUSE is auto-installed when missing: `scripts/ensure-reuse.sh` tries (in
order) `reuse` in PATH, `.venv/bin/reuse` if present, then creates
`.venv-reuse` and runs `pip install --require-hashes -r scripts/requirements-reuse.txt`,
then `pipx run` with `--spec` taken from that lockfile. Your `.venv` is never
created or modified. The lockfile is maintained for hash pinning (OpenSSF
Scorecard) and Renovate (`pip_requirements`); regenerate locally with
`pip-compile --generate-hashes scripts/requirements-reuse.in -o scripts/requirements-reuse.txt`
(needs **pip-tools**). You can also install manually: `pipx install reuse` or
`python3 -m venv .venv && .venv/bin/pip install --require-hashes -r scripts/requirements-reuse.txt`.

The `update_headers.py` script derives copyright from git history and applies
the *nontrivial change* threshold (~15 lines per author per file). See
[docs/NONTRIVIAL-CHANGE.md](docs/NONTRIVIAL-CHANGE.md) for the definition.

**.mailmap:** Contributors who use multiple email addresses should add a
`.mailmap` entry at the repository root to map alternate identities to a
canonical form. Format:
`Canonical Name <canonical@email.com> Alternate Name <alt@email.com>`. The
`make headers` script uses `git log --use-mailmap`, so `.mailmap` affects
which copyright lines are generated. `make check-header-duplicates` verifies
no file lists the same copyright holder twice (per `.mailmap` canonicalization).

## Cursor agent configuration

Project-scoped Cursor rules, skills, and hooks live under [`.cursor/`](.cursor/).

- **Agent workflow:** [`.cursor/rules/agent-workflow.mdc`](.cursor/rules/agent-workflow.mdc)
  (Plan/Ask read-only phases; stop after plan delivery; validation only after edits)
- **Pre-merge / CI validation:** [`.cursor/skills/pre-merge-check/SKILL.md`](.cursor/skills/pre-merge-check/SKILL.md)
- **Release preparation:** [`.cursor/skills/release-prepare/SKILL.md`](.cursor/skills/release-prepare/SKILL.md)
- **CI gates reference:** [`.cursor/rules/ci-validation.mdc`](.cursor/rules/ci-validation.mdc)

**Stop hook:** After each agent turn, the stop hook may auto-submit a follow-up
only when the agent edited files **this turn** (or when a scoped check failed on
the previous turn) and required targets have not succeeded yet. It does not
suggest `make check-fast` on read-only turns. Pending paths clear after all
scoped checks succeed. The `sessionStart` hook clears edit tracking;
`afterFileEdit` records agent-edited paths in both pending and per-turn files.

Hooks opt-out: set `VLZ_CURSOR_HOOKS_DISABLE=1` to skip Cursor hook scripts locally.

**Agent-assisted releases:** AI agents may run the release workflow
(including signed commits, a `release/vX.Y.Z` pull request merged to `main`,
tags, and `git push origin vX.Y.Z`) when a human **explicitly requests** it in
chat. Agents must **not** push directly to `origin/main` (branch protection
requires PR review). Agents must not start release work proactively. See
[`.cursor/skills/release-prepare/SKILL.md`](.cursor/skills/release-prepare/SKILL.md).
Human maintainers may still cut releases manually per [Versioning and
releases](#versioning-and-releases) below.

## Code style and checks

- If the existing code keeps variables, constants, and imports alphabetized,
  continue with that pattern. Ensure new files use alphabetized variables,
  constants, and imports.
- Run `make check` before submitting to verify headers, build, tests
  (`coverage-quick`), fuzz-changed (when relevant), dependency policy
  (`deny-check`, `cargo deny check`), and linters (fmt-check, clippy,
  lint-python, lint-shell). Use `make -j check` for faster runs
  (parallel execution).
- Follow the [Rust Style Guide](https://doc.rust-lang.org/beta/style-guide/index.html).
- The codebase uses `#![deny(unsafe_code)]`.
- Run `make fmt` to auto-format Rust code; run `make clippy` to verify lints.
  Both are included in `make check`; fix any failures before submitting.
- Python scripts in `scripts/` follow PEP 8, use line length 79, and pass
  `make lint-python` (modern-style checker, black, pylint, mypy, bandit).
  The Makefile auto-creates `.venv-lint` and installs the linters if they are
  not found. Python 3.11+ style is required for `scripts/` and
  `tests/scripts/`: do not use `from __future__ import annotations`; use
  built-in generics (`list[str]`) and PEP 604 unions (`str | None`) instead of
  legacy `typing` aliases (`List`, `Optional`, `Union`, etc.); import names
  that are in stdlib `typing` on 3.11+ from `typing`, not `typing_extensions`.
  Policy is enforced by [`scripts/python_modern_style.py`](scripts/python_modern_style.py).
- Shell scripts in `scripts/` follow
  [Google's Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
  (PRD NFR-022). Run `make lint-shell` (ShellCheck) before submitting.
  That target ShellChecks `scripts/*.sh`, `scripts/lib/*.sh` (from the
  `scripts/` directory with `-x` so sourced files resolve), and the committed
  bash completion
  `completions/vlz.bash` (generated by clap; SC2207 is suppressed for
  `completions/` via `completions/.shellcheckrc`). Install ShellCheck via your
  package manager (e.g. `apt install shellcheck`).
  Key rules: use `#!/usr/bin/env bash` or `#!/bin/bash`; 2-space indentation;
  max 80-character lines; prefer `$(command)` over backticks and `[[ ]]` over
  `[ ]`; quote variables (`"${var}"`); use `local` in functions; send error
  messages to stderr (`>&2`). The style guide is authoritative; this is a
  concise summary.
- **GitHub Actions (`ci.yml`):** Job `check` runs [`./scripts/run-check.sh`](scripts/run-check.sh)
  (full Makefile gate via `make check` with `--output-sync=target` and `-k` so
  independent targets keep running after a failure; batched failure summary at
  the end of the log and in the GitHub Actions step summary). Same gates as local
  `make -j check` (headers, `cargo deny`, third-party license file check, fmt,
  Clippy, Python and shell lint, fuzz-changed, coverage-quick). For a single
  failing target during local iteration, run that target directly (e.g.
  `make clippy`) instead of the full check. PRs also run DCO and commit
  signature jobs before `check`.
  **Merge queue (OP-019):** On `merge_group`, `scripts/check-dco.sh` and
  `scripts/check-signatures.sh` require two **full 40-character lowercase hex**
  SHA-1 values for their positional base/head arguments (after trim and
  lower-case). With two positional arguments in any **other** environment
  (local dev, `pull_request` CI, etc.), those scripts still accept any ref
  `git rev-parse` accepts (branches, tags, short SHAs). To reproduce merge-queue
  validation locally, set `GITHUB_EVENT_NAME=merge_group` and pass two full
  SHAs. Shared rules: [scripts/lib/ci-input-validate.sh](scripts/lib/ci-input-validate.sh).
  The workflow caches apt `.deb` archives for `shellcheck` and `afl++` (see
  comments in `ci.yml`) and installs `cargo-llvm-cov`, `cargo-deny`,
  `cargo-afl`, and `cargo-about` with [taiki-e/install-action](https://github.com/taiki-e/install-action)
  at a pinned action SHA and tool versions listed there (`cargo-deny` matches
  the Quick setup pin below). Rust for `check` is pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml); CI and release workflows use the
  host `rustup` (no `dtolnay/rust-toolchain` action) so the first `rustc` / `cargo`
  in the repo root provisions that channel and its components. Cargo
  cache keys stay stable. [Swatinem/rust-cache](https://github.com/Swatinem/rust-cache) restores
  registry, git, `target/`, and `~/.cargo/bin` (`cache-bin: true`). **Cache scope:**
  a re-run of the same workflow on the same ref can hit a cache saved by the prior
  attempt; a new PR branch restores from the default branch (`main`) and its own
  ref only (not other open PR branches). After a PR merges, its cache becomes
  available on `main`. The `check` job runs on `push` to `main` (not only on PRs)
  so merges seed the default-branch cache for later PRs. **Fork PRs** and brand-new
  branches may miss an exact rust-cache key until `main` or that ref has saved one;
  changing `Cargo.lock` always changes the key (prefix restores can still speed up
  compiles). **Why `push` to `main` is kept:** an optional merge queue on `main`
  can re-run CI via `merge_group` before merge, but in practice many merges use
  an admin bypass (unsatisfiable review rules for a sole contributor) and never
  trigger `merge_group`; for those merges, `push`-triggered CI is the only run
  against the exact commit on `main`. `merge_group` runs also execute on an
  ephemeral `gh-readonly-queue/*` ref, not `main`, so they do not seed the
  `main`-scoped cache that new PR branches restore from; only `push` to `main`
  and the nightly [`coverage-nightly.yml`](.github/workflows/coverage-nightly.yml)
  schedule (07:00 UTC) write to that scope. Nightly coverage uses the same
  `shared-key: check` and `CC` / `RUSTFLAGS` as the `check` job so exact-key
  rust-cache hits align across PR CI, push CI, and nightly. `cargo-deny` is installed only when missing from the restored
  `~/.cargo/bin` (pinned `CARGO_DENY_VERSION` in `ci.yml`; install-action provides
  a prebuilt binary for cold starts). The workflow logs `Rust cache exact key hit`
  and `cargo-deny present (skip install)` after restore.
- **OpenSSF Scorecard (`scorecards.yml`):** Nightly and
  **workflow_dispatch**; runs [OSSF Scorecard](https://github.com/ossf/scorecard-action)
  with SARIF uploaded to GitHub Code Scanning and **publish_results** for the
  README badge on [api.scorecard.dev](https://api.scorecard.dev). Uses the
  default **GITHUB_TOKEN** only (no PAT). See
  [`.github/workflows/scorecards.yml`](.github/workflows/scorecards.yml).
- **Super-linter:** CI runs the [super-linter](https://github.com/super-linter/super-linter)
  **slim** image in two modes: **incremental** (push/PR to `main`,
  `VALIDATE_ALL_CODEBASE=false`, job `super-linter` in workflow `ci.yml`) and
  **nightly full scan** (`VALIDATE_ALL_CODEBASE=true`, workflow
  `super-linter-nightly.yml`).
  The README badge reflects the **nightly** workflow (last full-tree run).
  Locally: `make super-linter` (incremental) or `make super-linter-full` (full
  tree); both call [`scripts/super-linter.sh`](scripts/super-linter.sh) and
  require Docker. Before opening a PR, `make check-fast` runs
  `make check-super-linter-native` (no Docker): OBS env key order, release
  workflow Checkov skip parity, and **codespell** from `.venv-test/bin`
  using [`.codespellrc`](.codespellrc) (same gate as super-linter
  SPELL_CODESPELL). Workflows pass `GITHUB_TOKEN` and set
  `SAVE_SUPER_LINTER_OUTPUT` / `SAVE_SUPER_LINTER_SUMMARY` so logs upload on
  failure. The script sets `IGNORE_GITIGNORED_FILES=true` and
  `FILTER_REGEX_EXCLUDE` so `target/`, `.git/`, `completions/` (ShellCheck is
  already `make lint-shell` with `completions/.shellcheckrc`), Python venvs
  (`.venv*/`), `.mypy_cache/`, `site-packages/`, and `super-linter-output/`
  (artifact tree when `SAVE_SUPER_LINTER_*` is on) are skipped. It sets
  `LINTER_RULES_PATH` to `.` so configs at the repository root apply (the
  default would be `.github/linters`; the workspace mount is `/tmp/lint`). It
  sets `YAML_CONFIG_FILE=.yamllint` so yamllint uses the repo
  [`.yamllint`](.yamllint) (GitHub Actions-friendly `truthy`/`comments` and
  longer lines for pinned `uses:` plus Zizmor ignore comments). It sets
  `BASH_EXEC_IGNORE_LIBRARIES=true`. **Canonical policy:** every
  `VALIDATE_*=false` toggle lives in
  [`scripts/super-linter.sh`](scripts/super-linter.sh); other linters follow
  super-linter defaults unless that script disables them.
  Summary: validators duplicated by `make -j check` are off (Rust editions and
  Clippy; Python black, pylint, mypy, and related super-linter Python tools
  including Ruff, Flake8, and isort, since `lint-python` uses black, pylint,
  mypy, and bandit only; shell shfmt and BASH; Markdown and Markdown Prettier;
  natural language). ESLint, TypeScript/JavaScript/Vue/JSX linters, and
  Prettier-family formatters (including JSON, JSONC, YAML, GraphQL, and HTML
  Prettier) are off; [`biome.json`](biome.json) covers **JSON, JSONC, CSS,
  JavaScript, TypeScript, JSX, TSX, and GraphQL** (via `files.includes`).
  **CSS Stylelint** (`VALIDATE_CSS`) and **CSS Prettier** stay off so Biome is the
  only tool on those paths. **YAML** is not handled by Biome; YAML in CI follows
  super-linter defaults with [`.yamllint`](.yamllint) at the repo root (YAML
  Prettier remains off). **Gitleaks** and **Zizmor** run with super-linter
  defaults ([`.gitleaks.toml`](.gitleaks.toml) is honored with
  `LINTER_RULES_PATH=.`). A few workflow lines use `# zizmor: ignore[...]`
  where maintainers chose pinned actions over script-only equivalents (see
  Zizmor docs). **JSCPD** stays off. You may still run `gitleaks detect` locally
  before push for faster feedback. The script defaults to a
  **pinned** slim image digest (linux/amd64, not `:slim-latest`, so linter
  versions stay stable until maintainers bump the digest). Override with
  `SUPER_LINTER_IMAGE` if needed. **Renovate** ([`renovate.json`](renovate.json))
  runs **twice weekly** (Monday and Thursday, **05:00 UTC**) per
  [`.github/workflows/renovate.yml`](.github/workflows/renovate.yml). It uses
  a **regex** custom manager to open PRs when the digest for
  `ghcr.io/super-linter/super-linter:slim-latest` changes. Another set of
  **regex** rules tracks **crates.io** versions for
  `cargo-llvm-cov`, `cargo-afl`, and `cargo-about` in the
  `taiki-e/install-action` `tool:` line in
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (**minor** and **patch**
  bumps are grouped into one PR). **`cargo-deny`** is pinned separately as job
  env `CARGO_DENY_VERSION` in `ci.yml` (install step uses that env) and as
  `cargo-deny@…` in [`.github/workflows/coverage-nightly.yml`](.github/workflows/coverage-nightly.yml);
  Renovate bumps both in one PR (`cargo-deny-workflow-pins`). A **regex** rule tracks the stable
  **channel** in [`rust-toolchain.toml`](rust-toolchain.toml) using the
  **github-tags** datasource for `rust-lang/rust` (**minor** and **patch**
  bumps are grouped into one PR; **major** upgrades stay separate). It also manages
  **GitHub Actions** under `.github/workflows/`: `uses:` lines are pinned to
  immutable commit SHAs with the release tag in a trailing YAML comment
  (`helpers:pinGitHubActionDigests`). **Minor** and **patch** action updates are
  grouped into **one** PR; **major** upgrades stay in **separate** PRs.
  Dockerfile base images still follow the `dockerfile` rules in
  [`renovate.json`](renovate.json).
  The **`pep621`** manager updates [`pyproject.toml`](pyproject.toml) (PEP 621
  `[project.optional-dependencies].dev` version floors for pytest, pytest-cov,
  black, pylint, mypy, and bandit). **`rangeStrategy: bump`** raises floors on
  new PyPI releases even when the old floor was still satisfied. **`minor`** and
  **patch** bumps are grouped into **`pyproject-dev-minor-patch`**.
  **`osvVulnerabilityAlerts`** is enabled for security-driven floor tightening;
  wide floors may still need a manual bump when OSV alerts do not fire.
  The **`cargo`** manager updates **workspace** Rust dependencies in
  `Cargo.toml` / `Cargo.lock` (**minor** and **patch** are grouped into
  **`rust-workspace-minor-patch`**).
  **Cargo**-related PRs use **`automerge: false`** (overrides the general
  non-major automerge rule) until maintainers re-enable after the rollout is
  verified.
  After Cargo updates, **`postUpgradeTasks`** run
  **`bash scripts/renovate-post-upgrade-licenses.sh`** once per branch
  (**`executionMode: branch`**). That wrapper installs **`cargo-about`** if
  needed, then runs **`scripts/generate-third-party-licenses.sh`**, the same
  script invoked by **`make generate-third-party-licenses`**, and
  **`make generate-sbom`** (commits **`sbom/**`** with **`THIRD-PARTY-LICENSES`**).
  After **`pyproject.toml`** PEP 621 dev dep updates, **`postUpgradeTasks`** run
  **`bash scripts/renovate-post-upgrade-sbom.sh`** to refresh **`sbom/**`** only. Containerbase
  **`installTools`** (**`rust`**, **`python`**) supplies the toolchain; the
  **`cargo-about`** pin matches
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
  The workflow sets **`RENOVATE_ALLOWED_COMMANDS`** (Renovate global
  **`allowedCommands`**) so that script is permitted; without it,
  **`postUpgradeTasks`** do not run.
  Keep **`constraints.rust`** in [`renovate.json`](renovate.json) aligned with
  the **`channel`** in [`rust-toolchain.toml`](rust-toolchain.toml).
  If regeneration fails because a new license needs an allowlist change, edit
  **`deny.toml`**, run **`make generate-third-party-licenses`**, and push to the
  Renovate branch.
  The workflow **job** uses **ubuntu-latest**; the **Renovate** process runs
  inside the **Renovate** Docker image on that runner, not on a bare Ubuntu
  shell.
  The config extends **`:gitSignOff`** so
  each Renovate commit includes **`Signed-off-by:`** in the message body, which
  satisfies [`scripts/check-dco.sh`](scripts/check-dco.sh) and the **check-dco**
  CI job (same expectation as `git commit -s` for humans).
  **`rebaseWhen`** is **`behind-base-branch`** so Renovate rebases open PR
  branches when **`main`** moves, reducing stale branches. **`platformAutomerge`**
  is **enabled** with **`automerge`** for **non-major** update types only
  (**minor**, **patch**, **digest**, **pin**); **major** PRs need a manual merge.
  For GitHub to merge automatically after CI, turn on **Allow auto-merge** in
  **Settings → General → Pull requests**, and use **branch protection** (or
  rulesets) on **`main`** so **required status checks** must pass before merge.
  **`prConcurrentLimit`** caps how many Renovate PRs may be open at once.
  Optional **merge queue** on **`main`** can serialize merges; configure it in
  GitHub alongside required checks.
  **GitHub App (not a PAT):** Create a
  [GitHub App](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps),
  install it on this repository (or org with repo access), and add secrets
  **`RENOVATE_APP_CLIENT_ID`** (GitHub App Client ID, `Iv1...`, from the app’s
  **About** page) and **`RENOVATE_APP_PRIVATE_KEY`**
  (full PEM from *Generate a private key*). Grant at least **Contents**,
  **Issues**, and **Pull requests** (read and write). For parity with
  [Renovate's GitHub App guidance](https://docs.renovatebot.com/modules/platform/github/#running-as-a-github-app),
  also enable **Checks**, **Commit statuses**, **Workflows** (read and write),
  **Dependabot alerts** (read), **Members** (read), **Metadata** (read), and
  **Administration** (read) on the app. The workflow uses
  [actions/create-github-app-token](https://github.com/actions/create-github-app-token)
  to mint a **short-lived installation token** for
  [renovatebot/github-action](https://github.com/renovatebot/github-action),
  which avoids a long-lived personal access token tied to a user account.
  The job sets **`RENOVATE_REPOSITORIES`** to **`${{ github.repository }}`**
  so Renovate targets the current repo; without it, the run logs *No
  repositories found* and does nothing.
  It also sets **`RENOVATE_ALLOWED_COMMANDS`** for **`postUpgradeTasks`** (see
  above).
  After merging a digest PR, run `make super-linter-full` and fix any new
  findings. **Manual upgrade:** resolve a new digest from
  `ghcr.io/super-linter/super-linter:slim-latest` (see comment in
  `super-linter.sh`), update `SL_SHA` / `DEFAULT_SUPER_LINTER_IMAGE`, run
  `make super-linter-full`, fix any new findings, then merge.
  [`biome.json`](biome.json) intentionally has **no** `$schema` URL so the Biome
  CLI in super-linter does not fail on schema-version mismatch when the image is
  bumped; use the Biome editor extension for IDE validation. Related repo files:
  [`biome.json`](biome.json), [`trivy.yaml`](trivy.yaml) (Trivy `db.no-progress`
  for quieter vulnerability DB downloads in the container),
  [`.codespellrc`](.codespellrc), [`.jscpd.json`](.jscpd.json) (local or future use;
  super-linter JSCPD is off), [`.gitleaks.toml`](.gitleaks.toml),
  [`.hadolint.yaml`](.hadolint.yaml), [`.yamllint`](.yamllint),
  [`.commitlintrc.json`](.commitlintrc.json).
- **Mermaid diagrams:** To view them in Cursor/VS Code, install the
  **Markdown Preview Mermaid Support** extension (or accept the workspace
  recommendation). Follow Mermaid diagram guidelines: no explicit colors or
  styling; use quoted labels for special characters (see project conventions).
- We **encourage** a **test-driven development (TDD)** approach (see below).
  Add unit tests in the crate that owns the logic; integration tests where
  appropriate. We may ask for tests to be added or updated before merging.
- Keep line lengths to less than 100 characters. Give a best effort at keeping
  line lengths below 80 characters (i.e., 79 characters or less) so that users
  with 80-character terminals can view the entire line, even when viewing
  patch files/diffs. Some lines can extend past this guideline when it improves
  readability (e.g., long URLs that can't be reasonably broken apart). This
  applies to source code and other text such as Markdown files, but does not
  apply to auto-generated files.
- In code comments and documentation, do not use em dashes or en dashes.
  Use `--` instead of em dashes, and `-` instead of en dashes.

### DRY (Don't Repeat Yourself)

Values reused across production and test code shall be defined in a single
central location (PRD NFR-024):

- **Configuration:** User-overridable values (parallel queries, TTL, paths,
  etc.) belong in `config.rs` and the config system. Add new keys per
  [Adding or updating configuration keys](#adding-or-updating-configuration-keys).
- **Constants:** Fixed values shared by production and tests (defaults, limits,
  filenames like `vlz-cache.redb`) should be `pub const` in the crate that owns
  them. Example: `config.rs` defines `DEFAULT_PARALLEL_QUERIES`,
  `DEFAULT_CACHE_TTL_SECS`; tests import these.
- **Derivation:** When a value can be computed (e.g. `5 * 24 * 60 * 60` for
  5 days), prefer deriving it or using a named constant over repeating the
  literal.
- **Per-crate constants:** Crate-specific values (e.g. `OSV_QUERY_URL` in
  vlz-cve-client, `NVD_BASE_URL` in vlz-cve-provider-nvd) stay in that crate.
  Cross-crate shared values live in the lowest common dependency (e.g. `vlz-db`
  or `vlz` config).

### CLI output (stdout)

In `vlz/src/main.rs`, use the `write_stdout()` helper for all user-facing
stdout (e.g. anything that would otherwise be `println!`). Do not use
`println!` for that. This ensures every command exits with code 0 when stdout
is a broken pipe (e.g. `vlz db show | less` then `q`), instead of panicking.
Stderr can stay as `eprintln!` or `log::error!`.

## Running tests and coverage

- **Run tests:** `make unit-tests` runs both `cargo test` and
  `make test-scripts`. To test only Rust: `cargo test --features vlz/testing`.
  The `vlz/testing` feature enables mocks and registry helpers for integration
  tests; release builds omit it for a smaller binary. To test a single crate
  (see MOD-005): `cargo test -p <crate>` (e.g. `cargo test -p vlz-cve-client`).
- **Exit-code matrix (DOC-004, FR-010):** Each standard exit code (0, 1, 2, 3,
  4, 5, 86) has a named integration test in
  [`crates/core/vlz/tests/exit_code_matrix.rs`](crates/core/vlz/tests/exit_code_matrix.rs).
  Subprocess smoke tests live in
  [`tests/scripts/test_exit_codes.py`](tests/scripts/test_exit_codes.py).
  Run `cargo test -p vlz --features vlz/testing exit_code_matrix` or
  `make test-scripts` (pytest includes exit-code tests).
- **Generate coverage (cargo-llvm-cov, XML for CI):** Use `cargo-llvm-cov` on
  the stable toolchain (default `rustup` toolchain) so instrumentation matches CI.
  1. Install cargo-llvm-cov: `cargo install cargo-llvm-cov --locked`
  2. Add LLVM tools to stable: `rustup component add llvm-tools`
  3. Run coverage from the repo root:
     - **Full run (CI):** `make coverage` -- runs fuzz first (cargo-llvm-cov +
       AFL improves metrics; NFR-012, NFR-020), then coverage. Slower (~90s+
       for fuzz).
     - **Quick run (dev):** `make coverage-quick` -- skips fuzz, runs coverage
       only. Use when you have not changed fuzz-relevant code.
     - Direct script: `./scripts/coverage.sh` (same as `make coverage-quick`).
     - The script uses the
       [external tests](https://docs.rs/crate/cargo-llvm-cov/latest#get-coverage-of-external-tests)
       workflow: `cargo llvm-cov show-env`, then `cargo build` and direct
       binary invocation, so the xtask binary is covered without depending on
       `cargo llvm-cov run`.
     - Reports: `reports/rust/html/index.html` (Rust HTML),
       `reports/cobertura-rust.xml` (Rust Cobertura), `reports/python/index.html`
       (Python HTML), `reports/cobertura-python.xml` (Python Cobertura).
     - Thresholds (NFR-012, NFR-017): Rust >= 85% line, >= 80% function, >= 85%
       region; scripts >= 95% line (aggregate and per `scripts/*.py` module).
       The coverage run **exits 1** when below these thresholds.
- **CI:** The Cobertura XML files (`reports/cobertura-rust.xml`,
  `reports/cobertura-python.xml`) are uploaded from GitHub Actions and used for
  PR coverage summaries (job `coverage-pr-comment` in
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
  **README coverage badges** come from SVGs published to the repository **wiki**
  by workflow
  [`.github/workflows/coverage-nightly.yml`](.github/workflows/coverage-nightly.yml),
  which runs `make -j coverage` (full fuzz and coverage) on a schedule and on
  `workflow_dispatch`. When that job fails before Cobertura is produced, the
  workflow still publishes grey **unknown** badges so README percentages do not
  stay stale. **One-time:** enable the GitHub wiki for the repo and create an
  initial wiki page so the wiki git remote exists; then trigger the workflow
  once (Actions tab) or wait for the nightly cron.
  GitHub Actions uses
  [taiki-e/install-action](https://github.com/taiki-e/install-action)
  for these Rust CLI tools in `.github/workflows/ci.yml`; see also
  [taiki-e/cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov).
- **PR coverage comments:** On pull requests where the head branch lives in
  the **same** repository (not from a fork), job `coverage-pr-comment` in
  `ci.yml` posts a sticky comment with Rust and Python line-coverage summaries
  (Cobertura). Fork PRs skip that job because the head repo is not the base
  repo.
- **CI check debug output:** [`scripts/run-check.sh`](scripts/run-check.sh) uses
  quiet defaults (`RUST_LOG=off`, `RUST_LOG_STYLE=never`, `cargo test --quiet`).
  For CI-like local runs, use `./scripts/run-check.sh`. **Verbose check mode**
  (`VLZ_CHECK_VERBOSE=1`): `RUST_LOG=info`, coverage phase markers, pytest `-v`,
  and full `cargo test` / probe output. Locally:
  `VLZ_CHECK_VERBOSE=1 ./scripts/run-check.sh`. On GitHub Actions, re-run the
  workflow with **Enable debug logging**; the `check` job sets
  `VLZ_CHECK_VERBOSE=1` when `runner.debug` is `1`. Coverage-only verbose:
  `VLZ_COVERAGE_VERBOSE=1 make coverage-quick`. AFL verbose:
  `VLZ_AFL_VERBOSE=1 ./scripts/fuzz.sh` (or `make fuzz`). Debugging a specific
  test: `RUST_LOG=info cargo test -p vlz --features vlz/testing -- --show-output`.
  Comments show **current** coverage for the PR head, not a diff versus
  `main`.

**[!NOTE]** Branch coverage is currently **disabled** in the default coverage
run (line, function, and region coverage only). Enabling `--branch` can
trigger an LLVM llvm-cov crash (SIGSEGV) when the report includes the
proc-macro crate. Until that toolchain bug is resolved, coverage reports show
line, function, and region metrics; branch threshold (70%) remains the target
when branch coverage is re-enabled.

**Linker:** `./scripts/coverage.sh` uses the default Rust linker (usually LLD).
If the coverage link step fails with LLD (e.g. invalid symbol index with
`instrument-coverage`), set **`VLZ_COVERAGE_USE_BFD=1`** to append
`-fuse-ld=bfd` on Linux when `ld.bfd` is available. Do not enable this if GNU
`ld.bfd` crashes (e.g. bus error); in that case stay on the default linker.

### Script testing (NFR-021)

- **Run script tests:** `make test-scripts` runs `pytest tests/scripts/ -v`.
- **Python dev dependencies:** [`pyproject.toml`](pyproject.toml)
  `[project.optional-dependencies].dev` is the single source of truth for
  version floors. `make setup` bootstraps `.venv-test` and `.venv-lint` via
  `pip install ".[dev]"` from the repo root. The `pytest>=9.0.3` floor
  remediates CVE-2025-71176 (insecure temp-dir handling in pytest through
  9.0.2).
- **Prerequisites:** Run `make setup` first, or `make test-scripts` will
  bootstrap `.venv-test` on demand.
- **Placement:** Script tests live in `tests/scripts/`; the `scripts/` package
  is imported via conftest path setup.
- **Coverage:** `make coverage` or `make coverage-quick` runs script tests
  with pytest-cov
  (`--cov=scripts --cov-fail-under=95`). Reports: `reports/python/index.html`,
  `reports/cobertura-python.xml`. Per-file modules under `scripts/*.py` must
  meet >= 95% line coverage; run `term-missing` locally to find gaps.

### Fuzz testing (NFR-020)

- **Three tiers:**
  - **Smoke (default):** `make fuzz` or `./scripts/fuzz.sh` runs all targets
    (~30 s each). Use for on-demand verification.
  - **Changed code only:** `make fuzz-changed` or `./scripts/fuzz.sh --changed`
    runs only targets whose mapped files changed. **Skipped** when
    none of the mapped files have changed (exit 0).
  - **Extended:** `make fuzz-extended` or `./scripts/fuzz.sh --extended` runs
    all targets with 30 min timeout each. Use for nightly or deep verification.
- **Mapping:** `scripts/fuzz-targets.map` maps each target to source paths.
  Add one mapping entry when adding a new fuzz target.
- **FUZZ_TIMEOUT:** Overrides per-target timeout (seconds). When unset: 30
  (smoke) or 1800 (extended).
- **Exit codes (FR-009):** The script exits 0 when no crashes (or when skipped);
  exits 1 when crashes are found. Crash paths written to
  `reports/fuzz-crashes.txt`.
- **Prerequisites:** [cargo-afl](https://github.com/rust-fuzz/afl.rs) and
  [AFL++](https://github.com/AFLplusplus/AFLplusplus). The first fuzz run clones
  and builds AFL++ under the XDG data dir via cargo-afl; on Debian/Ubuntu you
  typically need **build-essential**, **llvm-dev**, **clang**, and **git**
  so `make clean install` in that tree succeeds. When you change the default
  `rustc` (e.g. `rustup update`), `./scripts/fuzz.sh` reruns `cargo afl config --build`
  as needed and stores `rustc -vV` in `rustc-stamp-for-afl` next to the AFL++
  clone under `$XDG_DATA_HOME/afl.rs` (or `~/.local/share/afl.rs`). For unusual
  failures you can still run `cargo afl config --build` or `--build --force` by hand.
- **Targets:** `fuzz_config_toml`, `fuzz_requirements_txt`,
  `fuzz_parse_config_set_arg`. Seed corpus in `tests/fuzz/corpus/`.
- **Coverage:** `./scripts/fuzz.sh --coverage` integrates with cargo-llvm-cov
  (see
  [cargo-llvm-cov AFL docs](https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-afl-fuzzers)).

## Test scope and layering

Not every change needs a new pytest or Rust test. Place each assertion where
it earns its cost: **behavioral tests** for production logic, **make/lint/CI
gates** for config and wiring.

### Production code (strict TDD)

**In scope:** all Rust in `crates/**`; Python modules under `scripts/` with
branching, parsing, transformation, or I/O logic.

**AI agents:** follow the TDD workflow below (tests first, confirm fail,
implement). When editing `scripts/**/*.py`, keep each touched module at
**>= 95% line coverage** (target 100% where practical). See
[Script testing (NFR-021)](#script-testing-nfr-021) and
[Per-file Python coverage](#per-file-python-coverage).

**Human contributors:** TDD preferred; automated tests required before merge for
substantive behavior changes.

### Selective tests (reasonable value)

Add tests when they exercise **executable behavior** that existing gates do not
cover:

| Change type | Preferred verification |
| ----------- | ---------------------- |
| Shell release/OBS scripts | Subprocess with fixtures or dry-run |
| CI input contracts | Run validator scripts (`scripts/ci-input-validate.sh`) |
| Parallel-make hazards | Focused contract test or `make` invocation |
| Supply-chain pins | Hash/pin invariants with clear SEC/NFR tie |

### Do not add tests (use other gates)

**Discouraged:** `Path(...).read_text()` plus `assert "some string" in text` on
non-production files when any of these already apply:

- `make check`, `make check-fast`, `make check-packaging`, `make lint-shell`,
  `make super-linter`
- Dedicated check scripts (`scripts/check-obs-packaging.sh`, etc.)
- Schema/linters (ShellCheck, super-linter, Renovate schema)

Do not add tests for Makefile target lists, workflow step titles, Renovate
policy knobs, or file-exists checks for scripts already invoked by behavioral
tests unless documenting a non-obvious invariant (e.g. parallel-make ordering).

### Decision checklist

Before adding a test:

1. **Does this test execute code paths?** If no, prefer a make/lint gate.
2. **Would `make check` already fail on regression?** If yes, skip the test.
3. **Is the assertion about judgment (logic) or wiring (text)?** Judgment:
   unit test. Wiring: gate script or one subprocess smoke test.
4. **Would a rename/refactor break the test without breaking behavior?** If
   yes, the test is likely low value.

### Per-file Python coverage

Production Python lives in `scripts/*.py`. Aggregate coverage must meet NFR-012
(>= 95% line). Each production module should reach **>= 95% line coverage**;
aim for 100% where practical.

Before opening a PR that touches `scripts/**/*.py`, review gaps:

```sh
PYTHONPATH=. .venv-test/bin/python -m pytest tests/scripts/ \
  --cov=scripts --cov-report=term-missing:skip-covered -q
```

**Documented exceptions** (must be explicit, not silent):

- Thin `if __name__ == "__main__":` blocks that only parse args and call
  `main()` -- cover via subprocess test or `# pragma: no cover` after
  `main()` is tested directly
- Platform-only branches where the other branch is tested and documented
- Defensive I/O `except` blocks with a one-line comment and `# pragma: no cover`

Do not use "CI already checks it" to excuse untested `scripts/` logic. Do not
add `# pragma: no cover` without a one-line justification.

## Test-driven development (TDD)

We use **test-driven development** for **production logic** (Rust and Python
scripts): write tests that define the desired behavior first, then implement
code until those tests pass. TDD keeps requirements explicit, avoids
over-implementation, and gives a clear target for each change. Tests belong in
the crate that owns the logic (unit tests) or in the appropriate integration
test layout.

For Makefile-only, workflow-only, packaging-only, or documentation-only changes,
run the relevant `make check-*` targets instead of adding static text-assertion
tests. See [Test scope and layering](#test-scope-and-layering).

**Placement (Rust convention):** Unit tests live in the same file as the code
under test (or same crate) in a `#[cfg(test)] mod tests` block; integration
tests live in a top-level `tests/` directory or, for the binary, in tests that
run the built executable. **Documenting expected behavior:** Each test should
make the behavior it verifies clear--e.g. descriptive test names, a short `///`
doc comment tying the test to a requirement (e.g. FR-006, SEC-006), or
assertions that make the expected outcome obvious.

### TDD workflow

1. **Write tests** -- Define tests from expected inputs and outputs (or
   behavior) based on PRD requirements. When using an AI agent, be explicit
   that you are doing TDD so that agents do not create mock implementations for
   functionality that does not exist yet.
2. **Run tests and confirm they fail** -- Run the test suite and ensure the new
   tests fail for the right reason. Do not write implementation code at this
   stage.
3. **Commit the tests** -- Once the tests are satisfactory, commit them.
4. **Implement to pass** -- Write the minimal code that makes the tests pass.
   Do not change the tests to match the implementation; iterate on the code
   until all tests pass.
5. **Code coverage** -- Ensure code coverage meets or exceeds minimum
   thresholds. Add mocking if necessary, and iterate until coverage targets are
   satisfied.
6. **Commit the implementation** -- When all tests pass and you are satisfied,
   commit the implementation.

### Instructions for AI users

AI agents that read [AGENTS.md](AGENTS.md) are expected to follow TDD
automatically when adding or changing behavior. If you use an AI assistant to
contribute, you may instruct your agent explicitly using the steps below, or
rely on it reading AGENTS.md. If your agent is not following TDD, ensure it has
read AGENTS.md or include one of the prompts below in your request.

**Explicit prompts:**

- **Step 1:** "Write tests based on expected input/output pairs. We are doing
  TDD--do not create mock implementations for functionality that does not yet
  exist."
- **Step 2:** "Run the tests and confirm they fail. Do not write implementation
  code at this stage."
- **Step 3:** Commit the tests when satisfied.
- **Step 4:** "Write code that passes the tests. Do not modify the tests. Keep
  iterating until all tests pass."
- **Step 5:**: At this point, if mocking is required, implement it now and
  confirm code coverage thresholds are met.
- **Step 6:** Commit the implementation when satisfied.

### OpenSSF Best Practices (`test_policy` / `tests_are_added`)

The **test policy** for new behavior is the TDD workflow above plus
[Test scope and layering](#test-scope-and-layering). Production logic changes
need behavioral tests; wiring-only changes rely on make/lint gates. Merge
requests that add or change substantive behavior should include **automated
tests** when practical. When filing the OpenSSF Best Practices (passing)
questionnaire, use recent merged pull requests as evidence that tests
accompanied major changes.
Project entry: [bestpractices.dev](https://www.bestpractices.dev/en/projects/12361).

## Requirements

Full requirements (functional, non-functional, security, configuration) are in
[architecture/PRD.md](architecture/PRD.md). When adding features, align with
the relevant IDs (e.g. FR-*, NFR-*, SEC-*, CFG-*).
