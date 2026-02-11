# super‑duper (spd) – Requirements Specification
*Version 1.0 – 29 Jan 2026*

---  

## Table of Contents

1. [Purpose & Scope](#purpose--scope)  
   - [Design principles](#design-principles)
2. [Glossary](#glossary)
3. [Stakeholder Goals & Traceability Matrix](#goals--traceability)
4. [Functional Requirements (FR)](#functional-requirements)
5. [Non‑Functional Requirements (NFR)](#non-functional-requirements)
6. [Security Requirements (SEC)](#security-requirements)
7. [Operational / Deployment Requirements (OP)](#operational-requirements)
8. [Configuration Requirements (CFG)](#configuration-requirements)
9. [Modularity & Architecture (MOD)](#modularity)
10. [Documentation Requirements (DOC)](#documentation-requirements)
11. [Risk & Threat Model](#risk-threat-model)
12. [Appendices](#appendices)

---

### <a name="purpose--scope"></a>1. Purpose & Scope

**Goal** – Deliver an open‑source Software Composition Analysis (SCA) tool
written in Rust, named **super‑duper** (`spd`). The tool shall be:

* **Fast** – Scan large code-bases within seconds.
* **Accurate** – Minimize noise by only reporting vulnerabilities in reachable
code.
* **Modular** – Support via plug‑in crates.
* **Small** – Minimal binary size, static linking optional, cargo feature gates.
* **Extensible** – New languages, CVE providers, integrity check algorithms,
and report formats added without recompiling the core.
* **Reliable** – Deterministic exit codes, reproducible builds, high test
coverage.

**Why** – Provide developers with a free, developer‑friendly way to ensure
released software contains no known vulnerable dependencies and to generate
SBOMs to support a secure supply-chain.

The program's single purpose is software composition analysis for dependency
vulnerabilities; subcommands (scan, report, db, config, fp) are coherent tools
under that purpose and are designed to be scriptable and composable in CI and
pipelines. Requirements favor minimal scope and simplicity. New features,
formats, or options are added only when justified by user need or
interoperability. Complexity is accepted only where necessary; preference is
for small, well-defined interfaces and data-driven behavior where possible
(Rule of Representation). Performance targets (scan time, memory) are validated
by measurement (e.g., benchmark mode, FR‑029). Simplicity and transparency take
precedence over aggressive optimization; optimization is done after measuring
and only where needed.

### <a name="design-principles"></a>1.1 Design principles

**Unix Philosophy (TAOUP)** – The project aligns with the Unix philosophy
(ESR, *The Art of Unix Programming*): modularity (simple parts, clean
interfaces), clarity over cleverness, composition (scriptable,
pipeline-friendly output), separation of policy and mechanism, simplicity and
parsimony, transparency and robustness, least surprise, silence when nothing
to say, fail noisily when failing, and extensibility. Performance is validated
by measurement; simplicity is preferred over premature optimization.

**SOLID** – The codebase follows SOLID (Clean Code): single responsibility per
crate and per trait; open for extension via traits and Cargo features; trait
implementations are Liskov-substitutable; interfaces (traits) are narrow
(Interface Segregation); the core depends on abstractions (traits), not
concrete implementations (Dependency Inversion).

---

### <a name="glossary"></a>2. Glossary

| Term | Definition |
|------|------------|
| **SPD** | Short name for super-duper. |
| **CVE** | Common Vulnerabilities and Exposures identifier. |
| **SBOM** | Software Bill of Materials – a structured inventory of components. |
| **RedB** | Embedded B‑tree key/value store used for caching. |
| **Plugin crate** | A separate Rust crate implementing the public trait interfaces. |
| **Feature gate** | Cargo feature that enables optional code at compile time. |
| **SARIF** | Static Analysis Results Interchange Format (JSON). |
| **TLS** | Transport Layer Security – encrypted HTTPS communication. |
| **PASTA** | Process for Attack Simulation and Threat Analysis (threat modeling framework). |

---

### <a name="goals--traceability"></a>3. Stakeholder Goals & Traceability

| Business Goal | Requirement(s) |
|---------------|----------------|
| **Confidence in shipped code** | |
| **Low operational overhead** | |
| **Regulatory compliance (SOC 2, ISO 27001, CMMC)** | |
| **Developer productivity** | |
| **Future‑proof extensibility** | |
| **Networked or air-gapped environment** | |
| **Design principles (Unix / SOLID)** | [Design principles](#design-principles), MOD-001, MOD-002, NFR-013, FR-007 |

---

## <a name="functional-requirements"></a>4. Functional Requirements

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **FR‑001** | CLI entry point | Binary named `spd`; invoked as `spd <subcommand> [options]`. | **Given** the binary is installed, **when** the user runs `spd --help`, **then** usage information is printed to STDOUT and the process exits with code 0. |
| **FR‑002** | Program name | `--version` prints `super‑duper <semver>`. | Same pattern as FR‑01, expecting output `super-duper 1.0.0`. |
| **FR‑003** | License | Source released under **GPL‑3.0‑or‑later**. | Presence of `LICENSE` file containing SPDX identifier `GPL-3.0-or-later`. |
| **FR‑004** | Directory scanning | Scan a directory tree (default: cwd) for manifest files; positional argument overrides root. | `spd scan` scans cwd; `spd scan /my/project` scans the supplied path. |
| **FR‑005** | Manifest discovery (initial) | Detect all registered language plugins (Python, initially). For Python, the default manifest file names are **requirements.txt**, **pyproject.toml**, **Pipfile**, **setup.py**, and **setup.cfg**; this set is overridable via FR‑006 (per-language regex). | `spd list` prints `python`. |
| **FR‑006** | Configurable regexes | Users can add custom manifest‑file patterns per language. Patterns are evaluated in order, first match wins, and conflicts are resolved by user-defined order. | `spd config --set python.regex="^requirements\\.txt$"` stores the pattern; subsequent scans honor it. |
| **FR‑007** | Primary output format | Default: plain‑text table; `--format-type json|sarif` switches format. Default text output shall be suitable for piping and scripting (e.g., line-oriented or clearly delimited). JSON and SARIF are for programmatic consumers; when output is to stdout, it shall be unambiguous so that pipelines and wrappers can rely on it. Default table output is intended for both human read and simple parsing (e.g., by grep/awk or CI scripts). | `spd scan --format-type json` outputs valid JSON to STDOUT. Default table output is pipe- and script-friendly. |
| **FR‑008** | Secondary output formats | `--summary-file` can generate any combination of html,json,sarif files. | `spd scan -s html:/tmp/r.html,json:/tmp/r.json` creates both files. |
| **FR‑009** | CI‑friendly exit codes | Deterministic exit codes (see FR‑10). | In CI, `spd scan && echo OK` prints OK only when exit 0. |
| **FR‑010** | Exit‑code matrix | 0 normal, 1 panic, 2 mis‑config, 3 missing pkg‑mgr, 86 CVE found, configurable overrides (except 1 & 2). | `spd scan --exit-code 99` forces exit 99 on CVE condition. |
| **FR‑011** | CVE detection workflow | Resolve deps (including transitive) → query local database → on miss query online provider (default OSV.dev) → cache result with TTL. | After a scan, `spd db stats` reports cache hit‑rate and newly fetched CVEs. |
| **FR‑012** | Parallel online queries | Up to 10 concurrent queries by default; configurable up to 50 per provider. Values >50 must be rejected with a clear error (exit 2). | `spd scan --parallel 30` launches 30 concurrent HTTP requests. |
| **FR‑013** | Severity mapping | Severity is derived from the **primary CVSS score** (see FR‑034) using **configurable thresholds**. Default thresholds are defined **per CVSS version** (v2, v3, v4) so the default mapping can differ by version. Thresholds are overridable via configuration (config file, environment variables, CLI). **Reports that present severity display only the severity label** (e.g. CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), not the raw CVSS score. | (1) Severity is computed from the primary CVSS score using configurable thresholds. (2) Default thresholds are specified per CVSS version (v2, v3, v4 when applicable). (3) Any report format that presents severity shows the severity label derived from this mapping, not the raw score. |
| **FR‑014** | Threshold‑driven exit logic | Configurable `min-score` and `min-count`; First filter CVEs by score >= min-score; then count; if count >= min-count -> trigger exit 86. Default min-score is 0. If min-count is 0 (default), treat as "disable count check." | With `min-score=7.0` and `min-count=3`, exit 86 only if ≥ 3 CVEs meet the score of 7.0 or higher. |
| **FR‑015** | False‑positive handling | Mark/unmark CVEs with comment, timestamp, user/host info; stored in separate RedB DB with a unified version schema across all RedB databases; include a project_id column (optional) to scope FP markings. | `spd fp mark CVE‑2023‑1234 --comment "vendor bug"` creates a row; `spd fp unmark …` removes it. |
| **FR‑016** | False‑positive exit code | Default exit 0 when only false‑positives; override-able by configuration (CLI, env-vars, config file). | `spd scan --fp-exit-code 77` exits 77 when no real CVEs are present. |
| **FR‑017** | Reporting crate | Reads caches and renders reports; supports future formats via CLI flags. | `spd report -t json` prints JSON report. |
| **FR‑018** | Database‑listing CLI | `spd db list-providers` enumerates supported CVE providers; **`spd db show`** displays cache entries with TTL, added timestamp, and cache data (see FR-035). | Output of `spd db list-providers` includes `osv`. `spd db show` lists cache entries with key, TTL, added-at timestamp, and minimum cache data. |
| **FR‑019** | Provider selection CLI | `--provider <name>` forces a specific provider; invalid name ⇒ exit 2. | `spd scan --provider foo`
| **FR‑020** | Extensibility – language plugins | Adding a new language must not require changes to the core binary. Language support is provided through **trait implementations** (`ManifestFinder`, `Parser`, `Resolver`). | A new crate spd-java implements the traits and registers itself via a macro; spd discovers it at compile‑time using Cargo features. |
| **FR-021** | Pre-populate cache command | A future sub‑command (spd preload) shall connect to a remote CVE database and copy the CVE data to the local database cache without performing a full scan. (Placeholder for now.) | spd preload stores the CVEs in the cache database. |
| **FR-022** | Resolving dependencies  | Find and use package lock files by default (if present) to determine package versions. Supported manifest and lock file formats per language are defined in [Appendix A](#appendix-a-manifest-and-lock-files). Fallback to using a package manager (if available) in a clean virtual environment to generate a lock file that includes all dependencies and transitive dependencies (e.g. `pip freeze`). Finally, as a last option, if no package manager is found for the language, use a library (e.g., the `pep440` crate) to resolve the dependencies and their versions. Return error code 2 with the message "Unable to detect transitive dependencies. Try installing the package manager or generate a lock file before running spd." | Running `spd` in a repository with a requirements.txt file successfully finds all transitive dependencies. |
| **FR-023** | Temporary virtual-env | When a lock file isn't found, and a package manager such as pip is available, the program creates an ephemeral virtual environment, installs the dependency tree if necessary and captures the full dependencies. The virtual environment is destroyed after the scan. The virtual env lives under std::env::temp_dir() with a UUID prefix, and a Drop guard cleans it up (unless configured for debugging)| No permanent files left in $HOME/.cache after the run. |
| **FR-024** | Missing package-manager handling | If a required package manager (e.g., pip, cargo, npm) is not on $PATH and the configuration marks it as required, the program exits with code `3` and prints an OS‑specific hint (e.g., `apt‑get install python3‑pip`). | When configured with `--package-manager=true`, running `spd scan` on a machine without pip yields exit 3 and a helpful message. |
| **FR-025** | Static build support | The project shall be compilable with musl (or equivalent) and rustls on Linux so that the resulting binary runs in a scratch Docker container without external libraries. Static linking is optional for other OSes. | `docker run --rm -i alpine spd --version` works. |
| **FR-026** | Semantic versioning | All crates follow SemVer 2.0.0 Major bumps for breaking API changes, minor for new features, patch for bug fixes. | Release notes reflect the version bump policy. |
| **FR-027** | Internationalization (i18n) | Documentation, reporting, and messages shall be locale-aware and use UTF-8 encoding. Locale is derived from `LANG` and `LC_ALL` env vars. | |
| **FR-028** | Bash completion | Bash completion functionality for spd is installed by default | Running `spd <TAB>` produces the list of subcommands and options. |
| **FR-029** | Benchmark mode | The `--benchmark` option to `spd` shall disable use of the cache and the network, and limit parallelism to 1. | Running `spd --benchmark` provides metrics that can be unit-tested to confirm compliance with NFR-001. |
| **FR-030** | Cache consistency | The chosen DatabaseBackend implementation shall guarantee atomic, **append-only** writes (or equivalent transactional safety); updates replace entries atomically using a transaction, guaranteeing that a partially-written entry cannot be read. | |
| **FR-031** | Offline mode | The `--offline` option to `spd` skips all network calls and returns exit code 4 if any CVE lookup would require a remote request. | Running `spd --offline` with an empty cache results in exit code 4 and the message "CVE not found in cache, and unable to lookup CVE due to `--offline` argument. |
| **FR-032** | Reachability‑aware vulnerability detection | While scanning a manifest and its transitive dependency graph, the tool must analyze the source code of each identified package to decide whether a reported CVE is actually reachable from the entry‑point(s) of the consuming project. The analysis is performed by constructing an Abstract Syntax Tree (AST) (or, where a full AST is impractical, a Parse Tree) for the relevant source files and applying a data‑flow / control‑flow walk that tracks the propagation of vulnerable symbols (functions, classes, constants, etc.) into the project's call‑graph. The result is a reachability flag attached to each CVE record (`reachable: true/false/unknown`). Reachability analysis may be implemented as an optional or phased capability. Initial versions may report all CVEs with a reachability field of `unknown` or omit the field until the analysis is implemented, so that the core scan path remains simple and testable. | Initial or minimal implementation may set `reachable: unknown` for all CVEs; full AST/flow analysis may follow in a later phase. |
| **FR-033** | Database back-end health check | `spd db verify` shall invoke DatabaseBackend::verify_integrity. The default RedB back-end uses SHA-256 by default.| Running `spd db verify` provides clear output as to whether the verify failed or succeeded, and returns 1 if failure, or 0 for success. |
| **FR-034** | Primary CVSS score and version | Each CVE record shall store a single primary CVSS score (numeric) and a field identifying the CVSS version used for that score. The primary score shall be from the **latest CVSS version available** (preference: v4, then v3, then v2). If no score is available, both fields may be absent. Severity shown in reports is derived from this primary score (and its version) via the configurable severity mapping (FR‑013); reports present **severity**, not the raw score. | (1) CveRecord includes `cvss_score` and `cvss_version`. (2) When deriving from provider data, the chosen score is from the highest available version (v4 > v3 > v2). (3) Any report format that presents severity shows the **severity** derived from the primary score and version (via the configurable mapping), not the raw CVSS score in the main user-facing display. |
| **FR-035** | Cache display (`spd db show`) | The program shall support displaying the contents of the CVE cache database via **`spd db show`**. For each cache entry, the following must be visible: cache key (e.g. package name and version); **TTL** (effective TTL for that entry, in seconds or human-readable); **timestamp when the entry was added** to the cache (e.g. ISO 8601 or Unix seconds); **cached data** — at least a summary (e.g. number of vulns, CVE IDs). Optionally, full raw or derived CVE payload may be exposed via a format/verbosity option (e.g. `--format json`) so that all cache data is available for debugging or tooling. Minimum display: key, TTL, added-at timestamp, and summary of cached CVEs (count and CVE IDs). | `spd db show` lists each entry with key, TTL, added-at timestamp, and minimum cache data; with an optional format flag (e.g. `--format json`), full cache payload is included. |

---

## <a name="non-functional-requirements"></a>5. Non-Functional Requirements

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **NFR-001** | Performance -- scanning speed | Scanning a 10 GB source tree with ~10 k manifest files must complete in ≤ 30 seconds on a modern 8‑core CPU (while mocking CVE fetches). Validated via benchmark mode (FR‑029); see [Design principles](#design-principles) (simplicity over aggressive optimization). | Benchmark mode reports ≤ 30 s on reference hardware. |
| **NFR-002** | Memory footprint | Peak RAM usage shall stay below 200 MiB for the default Python‑only implementation. Measurement taken with cold cache and `--no-parallel` to isolate memory usage. Validated via measurement; see [Design principles](#design-principles). | `valgrind --tool=massif` shows ≤ 200 MiB. |
| **NFR-003** | Concurrency safety | All accesses to the caches must be thread-safe. Any DatabaseBackend implementation must be `Send + Sync` and internally protect concurrent access (e.g., via RwLock, transactions, or lock-free structures). | Race-condition tests with `loom` pass.
| **NFR-004** | TLS verification | All output HTTPS connections must validate server certificates and hostnames. | `spd scan` fails with a clear error when presented with a self‑signed cert, expired cert, or other invalid certificate. |
| **NFR-005** | Back-off strategy | On HTTP 429/5xx responses the client backs off exponentially (configurable base delay, max retries), respecting `Retry-After` headers. | Simulated throttling results in retries with increasing delays. |
| **NFR-006** | Build reproducibility | The binary must be reproducibly built with a pinned tool-chain (rustc 1.78.0 or later) and Cargo.lock committed. | `cargo build --release` produces identical SHA‑256 hash on two clean machines. |
| **NFR-007** | Portability | The program must run on Linux (glibc & musl), macOS (Intel & Apple‑silicon), and Windows (via MSVC). | CI matrix builds succeed on all three OS families. |
| **NFR-008** | No unsafe code | The entire code-base shall be compiled with `#![deny(unsafe_code)]`. Each backend crate must also deny `unsafe`. | `cargo clippy` reports zero violations. |
| **NFR-009** | Licensing compliance | All third-party crates must be compatible with GPL-3.0-or-later. | `cargo deny` passes with no violations. |
| **NFR-010** | Accessibility of configuration | Every configuration option can be set via (a) default, (b) system config, (c) user config, (d) environment variable (SPD_<NAME>), or (e) CLI flag. Precedence order is strictly enforced. | Changing a value in a lower-precedence source does not affect the final runtime value if a higher-precedence source defines it. |
| **NFR-011** | Documentation completeness | The repository shall contain: Contributor guide (style, crate-interface, trait definitions, extension points). User guide (installation, configuration precedence, CLI reference, exit-code table). API reference generated by `cargo doc`. | `cargo doc --open` displays a full set of pages; README.md links to them. |
| **NFR-012** | Test coverage | Unit tests + integration tests must achieve **>= 70% branch coverage** and **>= 90% functional coverage** (including doctest examples). | Coverage is measured with **grcov** using the **nightly** toolchain with `-C instrument-coverage -Z coverage-options=branch` and grcov with `--branch`; the report is emitted in **Cobertura XML** so CI/CD (e.g. GitHub Actions) can consume it. Build and run tests with `RUSTFLAGS` and `LLVM_PROFILE_FILE` set (e.g. `cargo +nightly test`), then run grcov with `-t cobertura --branch -o coverage.xml`; that report shows the required percentages including branch coverage. Exact commands are in CONTRIBUTING (DOC-007). |
| **NFR-013** | Logging & diagnostics | Errors that cause exit 2 or 3 must be logged to stderr with a clear, actionable message. Verbose mode (``-v/--verbose``) prints additional debug information. On successful completion, when no report or listing was requested, the program shall produce no output to stdout. Stdout is reserved for requested reports and listings; stderr is for errors and diagnostics. Verbose mode may add diagnostic output to stderr. | `spd scan -v` shows detailed steps; non-verbose run only prints summary. Successful run with no report requested produces no stdout. |
| **NFR-014** | Compatibility with CI systems | The JSON report schema conforms to a stable contract (documented) so downstream jobs can parse it reliably. | A sample GitHub Action consumes the JSON and fails/passes based on the exit code. |
| **NFR-015** | Compliance with security standards | The design and operation shall meet **SOC 2**, **ISO 27001**, and **CMMC** baseline requirements (data protection, audit logging, least-privilege operation). Compliance documentation and controls (e.g., audit logging, least-privilege) shall be implemented via well-defined interfaces so that the core tool remains simple, testable, and maintainable. | A compliance checklist is shipped with the repo and signed off by a security reviewer. |
| **NFR-016** | Explicit plugin-in discovery | Plug-ins must register themselves via a `spd_register!` macro that expands to a `lazy_static!` registry. The core binary iterates over this registry at runtime; the presence of a plug-in is controlled solely by Cargo feature flags. | |

---

## <a name="security-requirements"></a>6. Security Requirements (SEC)

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **SEC-001** | Threat model | The security documentation shall include a threat model defining the security objectives, non-objectives, assets, threats, and mitigations. It shall use the **PASTA** method and provide a  visual attack tree in ASCII text. | The threat model exists and has been reviewed by multiple human and LLM security reviewers with no outstanding issues. |
| **SEC-002** | TLS certificate validation | Every HTTPS request to an online CVE provider must verify the full certificate chain and the hostname. | A simulated man-in-the-middle with a self-signed certificate causes the request to abort and prints a clear error message. |
| **SEC-003** | Principle of least privilege | The binary never elevates privileges; it always runs with the effective UID/GID of the invoking user. No set-UID bits are created during installation. | Running `spd` under `sudo` does **not** result in a set-UID binary; the process UID remains the caller's UID. |
| **SEC-004** | Data integrity & authenticity | Cached CVE entries are stored unchanged; any modification to the redb files outside the program must be detectable via an optional integrity-check command using simple SHA256 hash by default (`spd db verify`) which can be enabled/disabled via Cargo feature gating. Mutually exclusive with SEC-005. | `spd db verify` reports "integrity OK" for untouched files and flags tampering when the file is altered manually. |
| **SEC-005** | Non-repudiation | Optional FIPS-204 signature of redb values enabled with Cargo feature gating. Mutually exclusive with SEC-004 | `spd db verify` reports "integrity OK (FIPS-204)" for untouched files and flags tampering when the file is altered manually. |
| **SEC-006** | Secure configuration loading | Configuration files are parsed with strict validation; unknown keys cause a fatal error (exit 2) with a helpful message. | Providing malformed TOML entry results in `Error: Unknown configuration key "foo_bar"` -- exiting with code 2. |
| **SEC-007** | Back-off & retry strategy | On HTTP 429 or 5xx responses the client backs off exponentially (configurable base delay, max retries). The strategy is deterministic and logged in verbose mode. | When the provider returns 429 repeatedly, the client waits 100ms, 200ms, 400ms... up to the configured maximum before giving up. |
| **SEC-008** | Credential-free operation | The tool never stores or transmits credentials; all network calls are unauthenticated public API requests. | No secret files are created in $HOME/.config/super-duper; an `strace` shows no credential usage. |
| **SEC-009** | Auditable logging | All error conditions that lead to exit codes 2 or 3 are written to **stderr** with timestamps and actionable hints. Verbose mode (`-v/--verbose`) adds debug-level logs. Stdout is reserved for requested reports and listings only; stderr is for errors and diagnostics (see NFR-013). | Running `spd scan` with a missing `pip` prints `ERROR [2025-09-11T14:32:01Z] pip not found --install via apt-get install python3-pip.` |
| **SEC-010** | Compliance baseline | The overall design satisfies the baseline controls of **SOC 2**, **ISO 27001**, and **CMMC** (data protection, auditability, least-privilege, secure communications). A compliance checklist is shipped with the repository and signed off by a security reviewer. Compliance documentation and controls shall be implemented via well-defined interfaces so that the core tool remains simple, testable, and maintainable. | The checklist document (COMPLIANCE.md) is present, up-to-date, and references each control mapped to a concrete implementation in code. |
| **SEC-011** | No unsafe code | The crate is compiled with `#![deny(unsafe_code)];` any introduction of `unsafe` blocks fails the build. | `cargo check` succeeds; adding `unsafe {}` triggers a compilation error. |
| **SEC-012** | Dependency license compatibility | All third-party crates must be compatible with **GPL-3.0-or-later**. The build pipeline runs `cargo deny` and fails on any violation. | `cargo deny check licenses` passes in CI. |
| **SEC-013** | Secure randomness | Any random identifiers (e.g., temporary virtual-environment names) are generated with the OS-provided cryptographically secure RNG (rand::thread_rng). | Generated names are unpredictable; `rand::random::<u64>()` is used, not `std::time::Instant`. |
| **SEC-014** | File permission hardening | Created directories/files for caches and ignore DB inherit restrictive permissions (`0755` for dirs, `0644` for files). The program refuses to use a DB file that is world-writable. | Attempting to run with a cache file mode `0666` aborts with exit 2 and a user-friendly error message. |
| **SEC-015** | Dogfooding | Given that the latest stable version of super-duper is installed, when running CI/CD super-duper shall itself be scanned with the latest stable version of super-duper to ensure there are no CVEs in its dependencies (both prior to release, and daily after release). | `spd scan </path/to/super-duper/source-code>` exits 0. |
| **SEC-016** | Supply-chain verification | A CI step verifies the signatures of all dependencies when building. | `cargo audit` shows no vulnerabilities.
| **SEC-017** | Input validation | All inputs shall first be sanitized and then validated using an allow-list (not a deny-list). | Running a fuzz tester covers all main code paths and fails to crash the program, but instead returns a user-friendly error message when invalid input is supplied. |
| **SEC-018** | Coordinated vulnerability disclosure | A top-level SECURITY.md describes how to securely contact the maintainer(s) using GPG-encrypted email to disclose security vulnerabilities responsibly. The document shall also contain links to the threat model and to test results, including fuzz testing, and the latest `spd scan` results. | A SECURITY.md file exists with guidance for those reporting vulnerabilities as well as information for users and links to the threat model and test results (including fuzzing and `spd scan` results). |
| **SEC-019** | Software bill of materials | When a change in the dependencies is detected, the CI/CD system shall produce an updated SBOM in both SPDX and CycloneDX formats. | An SBOM in both SPDX 3.0 and Cyclone DX 1.6 formats is available in the repository. |

---

## <a name="operational-requirements"></a> 7. Operational / Deployment Requirements (OP)

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **OP-001** | Installation method | Users install the binary via `cargo install spd`. The process works for both privileged (sudo) and non-privileged accounts. No set UID binaries are ever created. | `sudo cargo install spd` places the binary in `/usr/local/bin/`. `cargo install spd` places the binary in `$HOME/bin`, creating the directory if it doesn't already exist. The binary works without extra steps. |
| **OP-002** | Default cache locations (privileged) | When installed as root, the redb cache resides at `/var/cache/super-duper/spd-cache.redb`, and the false-positive DB at `/var/lib/super-duper/spd-ignore.redb`. | After privileged install, those files exist with correct permissions (owner root, mode 0660). |
| **OP-003** | Default cache locations (non-privileged) | When installed as a normal user, the cache lives under `$XDG_CACHE_HOME/super-duper/spd-cache.redb` (fallback to `~/.cache/super-duper/spd-cache.redb`). The ignore DB lives under `$XDG_DATA_HOME/super-duper/spd-ignore.redb` (fallback to `~/.local/share/super-duper/spd-ignore.redb`). | Running `spd` as a regular user creates those directories and files automatically. |
| **OP-004** | Override of DB paths | CLI options `--cache-db <path>` and `--ignore-db <path>` allow the user to point to arbitrary locations, overriding the defaults regardless of privilege level. | `spd scan --cache-db /tmp/mycache.redb` uses the supplied file. |
| **OP-005** | Fallback logic for mixed privilege runs | If a privileged install is executed by a non-privileged user, the program first looks for a user-specific DB (XDG location); if absent or cannot be opened, it falls back to the system-wide DB. | A non-root user on a machine with a system DB sees the user DB if it exists, otherwise the system DB. If the system DB doesn't exist or can't be read, use defaults and print a warning about any unreadable configuration files. |
| **OP-006** | Directory creation | Any missing parent directories for the cache or ignore DB are created automatically with permissions `0750` (directories) and `0640` (files) and the immediate parent directory (`super-duper`) with `0700`. Errors in creation cause `exit 2` with a clear message. | Removing `~/.cache/super-duper` and running `spd` recreates the directory structure with these permissions. |
| **OP-007** | Database migration | The first run creates redb trees (cve_cache, false_positive, metadata) automatically (printing a short informational message). | `spd db migrate` reports "Database up-to-date". |
| **OP-008** | Migration versioning | Migration versioning via **Rust migration functions** stored in `src/migrations.rs`. Each migration increments a `metadata::schema_version` key. | Adding a new migration increments the version and the program applies it on next start. |
| **OP-009** | Cache expiration | Each cache entry stores its **own** TTL (or equivalent expiry), not a single global value. The configuration key **cache_ttl_secs** (value in seconds) provides the **default** TTL; the default is **5 days** (432000 seconds). Only **new** writes use this default unless overridden. When **writing** an entry, an optional **per-entry TTL override** may be applied; if present, that entry uses the override instead of the default. The program shall support **updating the TTL of existing cache entries** after storage: for a single entry (e.g. by package key), for multiple entries (e.g. by pattern or explicit list), and for all entries. Updated entries retain their existing cached-at timestamp; only their TTL (and thus expiry) changes. Each entry stores an **added (cached-at) timestamp** so that display and diagnostics can show when the entry was added. Stored representation must allow both default and per-entry TTL so that expiry and `spd db show` can show the effective TTL per entry. Expired rows are treated as cache misses on read and refreshed on demand. Physical removal of expired entries from the store is best-effort (e.g. on database init or on write). | After 5 days (or the entry's TTL), a subsequent scan re-queries the provider for the same package. `spd db set-ttl` can change TTL for one, multiple, or all entries. |
| **OP-010** | TLS & back-off configurability | CLI options `--tls-verify, --backoff-base <ms>, --backoff-max <ms>` allow the user to tune security and retry behavior. | Disabling verification (--tls-verify=false) produces a warning and proceeds. |
| **OP-011** | Environment-variable naming | All configuration keys are exposed as **SPD_<UPPER_SNAKE_CASE>** (e.g., **SPD_CACHE_TTL_SECS**, **SPD_PARALLEL_QUERIES**). | Setting `export SPD_PARALLEL_QUERIES=20` influences the run. |
| **OP-012** | Help & version output | `spd --help` prints a comprehensive usage message; `spd --version` prints the program name, version, and license. | Both commands exit with code 0. |
| **OP-013** | Packaging | The program shall be packaged as crates. It shall also be packaged as the following: RPMs for Fedora, RedHat, CentOS, Rocky Linux, Alma Linux, SLES/SLED, and OpenSuse. DEB for Debian and Ubuntu. Ebuild for Gentoo. It shall be packaged for Arch Linux and Alpine. And it shall be deployed as a Docker image from scratch. | All package formats are available and tested to install and run correctly on each targeted OS. |
| **OP-014** | Update mechanism | Updates shall be done using the OS's package manager, `cargo install`, or by using the latest Docker image. | Running the OS's package manager update process, using the latest Docker image, or running `cargo install` results in **super-duper** being upgraded to the latest version. |
| **OP-015** | Cache TTL update | The program shall allow changing the TTL of cache entries **after** they are stored. The user can set a new TTL for: (1) a **single** entry (e.g. by package key such as `name::version`), (2) **multiple** entries (e.g. by pattern or by explicit list of keys), or (3) **all** entries. The cached-at timestamp of each entry is unchanged; only the TTL (and thus expiry) is updated. The CLI shall report clearly if the backend does not support TTL updates or if the selector is invalid (exit 2). | e.g. `spd db set-ttl <SECS> --entry "pkg::1.0"`, `spd db set-ttl <SECS> --all`, and optionally `spd db set-ttl <SECS> --pattern "requests*"` or `--entries "a::1,b::2"`. Exit 0 on success; clear error if backend does not support updates or selector is invalid. |

---

## <a name="configuration-requirements"></a>8. Configuration Requirements (CFG)

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **CFG-001** | Configuration file format | All configuration files (system-wide, per-user, and user-specified) shall be written in **TOML**. The parser must reject any file that is not valid TOML. | Supplying a malformed `super-duper.conf` causes the program to exit with code 2 and prints "Invalid TOML in configuration file ...". |
| **CFG-002** | System-wide configuration | Default system-wide config file location: `/etc/super-duper.conf`. Settings defined here have the lowest precedence (overridden by all other sources). | A setting placed only in `/etc/super-duper.conf` is applied when no higher-precedence source defines it. |
| **CFG-003** | Per-user configuration | Default per-user config file location: `$XDG_CONFIG_HOME/super-duper/super-duper.conf` (fallback to `~/.config/super-duper/super-duper.conf`). This file has the second-lowest precedence. | When a user creates `~/.config/super-duper/super-duper.conf`, its values override the system-wide ones. |
| **CFG-004** | User-specified configuration file | The CLI must expose options `-c/--config <PATH>` that lets the user point to an alternative per-user config file. When this option is used, the supplied file replaces the default per-user file but retains the same precedence level (i.e., it still overrides the system-wide file and is overridden by env-vars and CLI flags). | `spd scan -c /tmp/custom.conf` loads settings from `/tmp/custom.conf` and ignores ~/.config/super-duper/super-duper.conf. |
| **CFG-005** | Environment-variable overrides | Every configuration key is also exposed as an environment variable prefixed with **SPD_** (e.g., **SPD_CACHE_TTL_SECS**). Environment variables have higher predence than any configuration file, but lower precedence than explicit CLI flags. | Setting `export SPD_PARALLEL_QUERIES=30` changes the parallelism even if the same key is defined in a config file. |
| **CFG-006** | Command-line overrides | All configuration options are individually addressable via CLI flags (e.g., **--cache-ttl-secs**, **--parallel-queries**). CLI flags have the highest precedence and override everything else. | Running `spd scan --parallel-queries 40` forces the value to 40 regardless of any config file or env-var. |
| **CFG-007** | Precedence order (summary) | The effective value for any option is resolved in the following order (high -> low): 1. CLI flags, 2. Environment variables (SPD_*), 3. User-specified config file (`-c/--config`), 4. Default per-user config file, 5. System-wide config file. | Changing a lower-precedence source never affects the final value if a higher precedence source defines the same key. |
| **CFG-008** | Validation & error handling | If any configuration source (file, env-var, CLI) contains an unknown key, an invalid value type, or malformed TOML, the program must exit with code 2 and display a clear diagnostic message including the offending source. Unknown CLI flags are caught by clap (exit 2) | Providing `SPD_UNKNOWN_OPTION=1` results in "Error: unknown configuration key 'UNKNOWN_OPTION" (from environment)" and exit with code 2. |

---

## <a name="modularity"></a>9. Modularity & Architecture (MOD)

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **MOD-001** | Separate crates for distinct responsibilities | The project shall be split into seven top-level crates (all published under the same workspace): 1. `spd-manifest-finder` -- discovers manifest files on disk. 2. `spd-manifest-parser` -- parses each manifest and resolved direct & transitive dependencies. 3. `spd-cve-client` -- queries online CVE providers (currently OSV.dev) and handles parallelism, back-off, and TLS verification. 4. `spd-db` -- defines the public trait DatabaseBackend that abstracts all persistent storage operations. 5. `spd-db-redb` -- default implementation of DatabaseBackend backed by RedB (`spd-cache.redb` and `spd-ignore.redb`). 6. `spd-report` -- reads data from the chosen DatabaseBackend implementation and emits reports (JSON by default, extensible to other formats). 7. `spd-integrity` -- ensures the integrity of the databases using SHA256 by default, extensible to FIPS-204, FIPS-205, etc. | Building the workspace produces distinct library crates (`cargo build -p spd-manifest-finder`, etc.) and a binary crate `spd` that depends on them. |
| **MOD-002** | Public trait contracts | Each crate shall expose a small set of **public traits** that define the contract for plug-ins. Traits may use `async fn` where appropriate. - ManifestFinder (async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError>). - Parser (async fn parse(&self, manifest: &Path) -> Result<DependencyGraph, ParserError>). - Resolver (async fn resolve(&self, graph: &DependencyGraph) -> Result<Vec<Package>, ResolverError>). - CveProvider (async fn fetch(&self, pkg: &Package) -> Result<FetchedCves, ProviderError>); returns a cacheable raw form plus derived Vec<CveRecord>. - DatabaseBackend (async_trait): init; get(&self, pkg) -> Result<Option<Vec<CveRecord>>, DatabaseError> (per-package; one package may have many CVEs); put(&self, pkg, raw_vulns: &[Value], ttl_override: Option<u64>) -> Result<(), DatabaseError> (store raw JSON for TTL/cache; if ttl_override is None, backend uses default TTL from config); set_ttl(selector, new_ttl_secs) for updating TTL of existing entries (one, multiple, or all; backends that do not support updates may return an error or no-op); list_entries() -> Result<Vec<CacheEntryInfo>, DatabaseError> (optional; each entry has key, TTL or expires_at, added_at, and cache data summary or full; backends that do not support listing may return an empty list or unsupported); stats; verify_integrity. Backends store at least expiry (or TTL), added-at timestamp, and raw/derived CVE data per entry. - Reporter (async fn render / render_to_writer / render_to_path). - IntegrityChecker (async fn verify(&self, db: &dyn DatabaseBackend) -> Result<(), IntegrityError>). | Adding a new language, database backend, CVE provider, integrity checker algorithm, or report format only requires implementing the relevant traits in a separate crate; the core binary can load it without recompilation. |
| **MOD-003** | Feature-gate extensibility | Optional language support, integrity checker algorithms, reporting output formats, and additional CVE providers shall be gated behind Cargo **features** (e.g., feature = "java" enables the Java manifest finder/parser). The default feature set includes only **Python** support, **SHA256** integrity checks, **JSON** reports, and **OSV** CVE provider. Feature flags shall allow independent toggles where applicable (e.g., `network`, `docs`). The `default` feature set is documented (e.g., in CONTRIBUTING or crate docs). Building with `--no-default-features` produces a minimal binary; which capabilities are omitted shall be documented. | `cargo build --no-default-features --features java` compiles the Java modules; omitting the feature leaves the binary smaller. |
| **MOD-004** | Zero-dependency core | The `spd` binary shall depend only on the internal crates and on minimal external crates (`clap`, `serde`, `tokio`). No heavy runtime frameworks are allowed. | `cargo tree` shows a shallow dependency graph (<30 direct crates). |
| **MOD-005** | Testing isolation per crate | Each crate must contain its own unit-tests and, where appropriate, integration-tests that mock external services (e.g., a local HTTP server for `spd-cve-client`). Test coverage goals (>= 70% branch, >=90% functional) apply **per crate**. | Running `cargo test -p spd-cve-client` exercises the HTTP client with a mock server and reaches the required coverage. |
| **MOD-006** | Documentation per crate | Every public trait, struct, and function in each crate shall have a `/// doc` comment. `cargo doc --open` must generate a complete API reference for each crate. | The generated docs contain no "missing documentation" warnings from `cargo rustdoc`. |
| **MOD-007** | Versioning consistency | All crates share the same **semantic version** (workspace version). A change that alters any public API bumps the **major** version for the whole workspace. Adding a new language, provider, or feature bumps the **minor** version. Bug-only changes bump the **patch** version. | Publishing `v1.2.0` adds a new `go` manifest finder; the workspace version is updated accordingly. |
| **MOD-008** | Future-proof extensibility | The architecture shall allow **future subcommands** (e.g., `spd preload`, `spd export-sbom`) to be added via plug-ins reusing the existing libraries without duplication. | Adding a new subcommand `spd preload` that depends on `spd-db` compiles and runs. |
| **MOD-009** | Feature-gated man pages | Optional man page documentation included via `spd help` by default. When documentation is omitted and `spd help [subcommand]` is called, print a message "Error: spd was built without documentation. To rebuild with documentation, run `cargo build`, or find the documentation online at <URL>." and exit with code 2. Which capabilities are omitted in a minimal build is documented (see MOD-003). | `cargo build --no-default-features` compiles spd without documentation leaving a smaller binary. |
| **MOD-010** | Feature-gated networking | Optional networking support included by default. To make a smaller air-gapped binary, allow `cargo build --no-default-features` to build spd without network support (remove `reqwest` and any other networking dependencies). Which capabilities are omitted in a minimal build is documented (see MOD-003). | `cargo build --no-default-features` compiles spd without network support leaving a smaller binary. |

---

## <a name="documentation-requirements"></a>10. Documentation Requirements (DOC)

| ID | Title | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| **DOC-001** | User guide (README.md) | A top-level README.md that explains installation (e.g., `cargo install`), basic usage, configuration precedence, CLI reference, and the exit code table. Includes quick-start examples for Python manifests. Includes links to other documents. | New users can follow the guide and run a successful scan without consulting any other material. |
| **DOC-002** | Developer guide | A CONTRIBUTING.md describing the crate architecture, public traits (`ManifestFinder`, `Parser`, `Resolver`, `Reporter`, `DatabaseBackend`), extension points, and how to add a new language plug-in. | Contributors can implement a new language crate by following the step-by-step instructions. |
| **DOC-003** | Configuration reference | Detailed documentation of every configuration key, its default value, accepted types, corresponding environment variable (`SPD_<NAME>`), and CLI flag that overrides it. Presented in a table for quick lookup. The CLI reference shall also document `spd db show` (including e.g. `--format` for output format) and `spd db set-ttl` (including options such as `--entry`, `--all`, `--pattern`, `--entries`). | Running `spd config --list` prints the same table as the docs. `spd db show` and `spd db set-ttl` are documented with their options. |
| **DOC-004** | Exit-code | A dedicated section enumerating all exit codes (0, 1, 2, 3, 86, plus any user-defined overrides) with the exact circumstances that trigger each. | Automated test verifies that each exit code is reachable via a scripted scenario. |
| **DOC-005** | Report formats specification | JSON schema definition for the default report, plus a roadmap for future formats (ASCII table, HTML, SDPX, CycloneDX, SARIF). The schema is versioned and published under `schemas/v1/report.json`. Bump the path with the schema changes (e.g., v2). Include a $schema reference. | Consumers can validate a generated report against the schema using `ajv` or similar tools. |
| **DOC-006** | Migration & versioning docs | Explanation of DatabaseBackend functionality describes how each backend may have its own migration scheme (RedB schema version, SQLite schema version) and that `spd db migrate` delegates to the active backend. | Running `spd db migrate --dry-run` prints the pending migration steps. |
| **DOC-007** | Testing & coverage guidelines | Instructions for running the full test suite, interpreting coverage reports (**grcov**, Cobertura XML), and guidelines for adding new unit/integration tests. | CI badge shows "Coverage >= 70% branch, >= 90% functional." |
| **DOC-008** | Security & compliance overview | Summary of the security requirements (as listed above) and the mapping to SOC 2, ISO 27001, and CMMC controls. Includes the location of the COMPLIANCE.md checklist. | Auditors can locate the compliance matrix quickly. |
| **DOC-009** | Release process & semantic versioning | Clear policy for bumping major/minor/patch versions, changelog generation (CHANGELOG.md), and publishing to crates.io. | Each tagged release on GitHub follows the described versioning rules. |
| **DOC-010** | FAQ & troubleshooting | Common error messages (missing `pip`, DB permission issues, TLS failures) with suggested remediation steps. Every error path dfined in the requirements appears in the FAQ with a suggested fix. | Users can resolve typical problems without opening a new issue. |
| **DOC-011** | API reference (Rustdoc) | All public crates are documented with `///` comments; `cargo doc --open` generates a browsable HTML reference. | The generated docs contain no undocumented public items. |
| **DOC-012** | License & attribution | The repository includes a LICENSE file (GPL-3.0-or-later) and a NOTICE file listing third-party licenses. | Both files exist and `cargo deny check-licenses` passes. |
| **DOC-013** | Man pages | Install  `man` pages to the standard locations on Unix systems when using the program's package manager. Also make the man pages available via `spd help` and `spd help <subcommand>`. | `man spd` shows the manual for super-duper. `spd help` shows the same man page for super-duper. |

---

## <a name="risk-threat-model"></a>11. Risk & Threat Model

This section satisfies SEC-001. The project uses the **PASTA** (Process for
Attack Simulation and Threat Analysis) method and provides a high-level
threat model. A full threat model should be reviewed by human and/or LLM
security reviewers with no outstanding issues.

### 11.1 Security objectives

- **Confidentiality:** Cached CVE data and false-positive markings are
  stored locally; the tool does not transmit user code or dependency
  graphs to third parties beyond public CVE API requests (package name +
  version).
- **Integrity:** Cached data and configuration are protected from
  tampering (SEC-004, SEC-005); strict config validation (SEC-006).
- **Availability:** Deterministic exit codes and clear errors so that CI
  and operators can rely on the tool.

### 11.2 Non-objectives

- The tool does not authenticate to CVE providers (SEC-008); it is
  credential-free.
- No guarantee of real-time CVE feed; cache TTL and offline use are
  by design.

### 11.3 Assets

- Local cache and ignore (false-positive) databases.
- Configuration files (system and user).
- Output reports (JSON, SARIF, HTML) that may contain CVE details.

### 11.4 Threats and mitigations

| Threat | Mitigation |
|--------|------------|
| Tampering with cache/ignore DB | Integrity check (`spd db verify`), file permission checks (SEC-014). |
| MITM or spoofed CVE provider | TLS verification, hostname validation (SEC-002, NFR-004). |
| Malformed or malicious config | Strict validation, unknown keys cause exit 2 (SEC-006). |
| Information disclosure via reports | Reports are written to user-specified or default paths; no unsanitized secrets. |
| Supply-chain compromise of dependencies | License checks (SEC-012), `cargo audit` (SEC-016), dogfooding (SEC-015). |

### 11.5 Attack tree (ASCII)

```
                    [Compromise spd user outcome]
                                    |
        +-------------------+------+------+-------------------+
        |                   |             |                   |
 [Tamper cache]    [Spoof CVE API]  [Malicious config]  [Compromise deps]
        |                   |             |                   |
   (verify_integrity,   (TLS verify,  (strict parsing,    (cargo deny,
    file perms)          cert chain)   exit 2)             audit, SBOM)
```

---

## <a name="appendices"></a>12. Appendices

### <a name="appendix-a-manifest-and-lock-files"></a>Appendix A: Supported manifest and lock files (by language)

| Language | Manifest files (discovered by default or via config) | Lock files (used for transitive resolution when present) |
|----------|------------------------------------------------------|----------------------------------------------------------|
| **Python** | requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg | poetry.lock, Pipfile.lock (planned). Initial implementation parses requirements.txt only. |
