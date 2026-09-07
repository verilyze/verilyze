<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# FAQ and Troubleshooting (DOC-010)

Common error messages and suggested remediation steps. See also
[architecture/PRD.md](../architecture/PRD.md) for requirements, and
[README.md](../README.md) for configuration and exit codes.

---

## CLI contract (cross-OS)

`make cli-contract` runs a subprocess suite against `CLI_CONTRACT_BINARY`
(or a locally built `vlz`). Use `CLI_CONTRACT_MODE=smoke` for the PR/release
gate subset, or `full` for Appendix A fixtures. This target is **not** part
of `make check`; GitHub Actions runs it on Ubuntu, macOS, and Windows.
Smoke includes one `--offline` lock-backed scan per default language.

Tag publish (`release.yml`) downloads **draft** GitHub archives, verifies
checksums and Cosign bundles, installs the native `vlz`, then runs smoke.
That gate runs **before** the release leaves draft. The nightly
`verilyze` workflow still installs the **published** latest Linux archive
(SEC-015). Failures after publish require a new patch version, not a tag
move.

Known limits: Linux musl is not a GitHub archive; Windows has no first-class
Bash/Zsh/Fish install (generation plus zip layout only). Default lock-less
Python, JavaScript, Java, and Ruby scans exit 4. Lock-less `--offline` is
FR-022a DirectOnly (never unqualified `No vulnerabilities found.`).

## SBOM inventory input (FR-038)

**Cause:** You have an existing CycloneDX or SPDX JSON SBOM and want CVE
analysis without re-resolving from language manifests.

**Remediation:** Pass `--from-sbom PATH` (repeatable) and/or place allowlisted
files under the scan root (`bom.json`, `sbom.json`, `*.cdx.json`,
`*.spdx.json`). Import accepts **CycloneDX 1.x** JSON and **SPDX 2.2 / 2.3 /
3.0** JSON. Packages need a supported Package URL (purl) with version;
unsupported components are skipped with a warning. Empty but valid SBOMs
complete as transitive coverage with zero packages (exit 0 when no CVEs).
Malformed or unrecognized JSON exits **4** (`failed_parse`). Embedded BOM
vulnerability sections are ignored; CVE lookup uses the configured provider.
Scan **output** SBOMs remain CycloneDX 1.6 and SPDX 3.0 (FR-017).

```sh
vlz scan --from-sbom sbom.cdx.json
vlz scan --from-sbom inventory.spdx.json /path/to/project
vlz preload --from-sbom bom.json
```

## Docker

### Docker cache files owned by root

**Cause:** The container runs as root by default. When you mount
`~/.cache/verilyze` for persistent cache, files created inside the
container are owned by root on the host.

**Remediation:** Use `--user "$(id -u):$(id -g)"` so the container runs
as your user. Ensure the cache directory exists before the first run:
`mkdir -p ~/.cache/verilyze`. See [README -- Running with
Docker](../README.md#running-with-docker).

### Docker image uses an in-memory CVE cache

**Cause:** The published Docker build enables the `mem` feature
(`runtime-mem`): CVE results are cached only for the lifetime of the
process. No `vlz-cache.redb` is written. `--cache-db` / `VLZ_CACHE_DB` exit
with code 2 in that build.

**Remediation:** For durable cache across container runs, use a desktop /
non-Docker build with the `redb` feature, or mount a persistent cache volume
only with a RedB-enabled binary. False-positive markings use portable JSON
(`vlz-ignore.json`); mount the same file into Docker:

```sh
vlz fp mark CVE-2024-1234 --comment "vendor" --ignore-db ./vlz-ignore.json
docker run --rm -v "$PWD:/src:ro" \
  -v "$PWD/vlz-ignore.json:/ignore.json:ro" \
  verilyze scan /src --ignore-db /ignore.json
```

Legacy `vlz-ignore.redb` is not readable in the Docker (mem) image; migrate
or re-mark into JSON first (desktop builds auto-migrate the default path when
the JSON file does not yet exist). Concurrent `vlz fp mark` uses an advisory
lock so distinct CVE markings are not lost across processes.

---

## Commit signing

### GPG: `gpg: signing failed: No secret key`

**Cause:** The key ID in `git config user.signingkey` does not match any key
in your GPG keyring, or the email on the key does not match `user.email`.

**Remediation:** Run `gpg --list-secret-keys --keyid-format=long` to find
your key ID, then `git config user.signingkey <KEY_ID>`. Ensure the email
on the key matches `git config user.email`.

### GPG: `gpg: signing failed: Inappropriate ioctl for device`

**Cause:** GPG cannot open a pinentry dialog (common in SSH sessions or
headless environments).

**Remediation:** Add `export GPG_TTY=$(tty)` to your shell profile
(e.g. `~/.bashrc`) and reload it.

### GPG: Passphrase prompt not appearing

**Cause:** The GPG agent is stuck or misconfigured.

**Remediation:** Restart the agent: `gpgconf --kill gpg-agent`, then retry
the commit.

### SSH: `error: Load key ... No such file or directory`

**Cause:** The path in `git config user.signingkey` does not point to a
valid SSH key file.

**Remediation:** Verify the path: `ls ~/.ssh/id_ed25519.pub` (or whichever
key you use). Update with
`git config user.signingkey ~/.ssh/id_ed25519.pub`.

### SSH: `make check-signatures` fails with "key not in your keyring"

**Cause:** The allowed signers file is missing or does not contain your
public key. Strict mode requires local signature validation.

**Remediation:** Create or update the allowed signers file:

```sh
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" \
    >> ~/.ssh/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

### Commits show "Unverified" on GitHub

**Cause:** Your public key (GPG or SSH) is not uploaded to GitHub, or the
email on the key does not match any verified email on your GitHub account.

**Remediation:** Upload the key at GitHub > Settings > SSH and GPG keys. For
SSH, add it as a **Signing key** (not just Authentication). Ensure the email
on the key matches a verified email on your GitHub account.

### `make check-signatures` fails with "no signature"

**Cause:** The commit is unsigned. `commit.gpgsign` may not be enabled.

**Remediation:** Enable signing: `git config commit.gpgsign true`. Amend
the unsigned commit: `git commit --amend --no-edit -S`. See
[CONTRIBUTING.md -- Commit signing setup](../CONTRIBUTING.md#commit-signing-setup).

### `make check-signatures` fails with "BAD signature"

**Cause:** The signature is corrupt or the commit data was altered after
signing.

**Remediation:** Amend and re-sign: `git commit --amend --no-edit -S`.

### `make check-signatures` fails with "EXPIRED" or "REVOKED key"

**Cause:** The signing key has expired or been revoked.

**Remediation:** Renew or replace the key, then re-sign affected commits
with `git rebase --exec 'git commit --amend --no-edit -S' <base>`.

---

## Exit code 2 (Misconfiguration)

### Invalid TOML in configuration file

**Message:** `Invalid TOML in configuration file
~/.config/verilyze/verilyze.conf: ...`

**Cause:** The configuration file contains syntax that is not valid TOML.

**Remediation:** Fix the TOML syntax. Common issues: unclosed quotes, trailing
commas, invalid escape sequences. Use a TOML validator or check the
[TOML spec](https://toml.io/).

---

### Unknown configuration key

**Message:** `Unknown configuration key 'foo' (from user)`

**Cause:** A key in the config file is not recognized (SEC-006).

**Remediation:** Remove the unknown key or fix the key name. Run
`vlz config --list` to see supported keys. For per-language regex patterns, use
`[python].regex` or `[rust].regex` (see FR-006).

---

### Parallel queries too high

**Message:** `Parallel queries must be at most 50; got 51`

**Cause:** `--parallel` or `VLZ_PARALLEL_QUERIES` exceeds the maximum (FR-012).

**Remediation:** Use a value ≤ 50, e.g. `vlz scan --parallel 50` or
`export VLZ_PARALLEL_QUERIES=50`.

---

### Unknown provider

**Message:** `Unknown provider: foo (use 'vlz db list-providers' to list)`

**Cause:** `--provider` names a provider that is not registered (FR-019).

**Remediation:** Run `vlz db list-providers` to see available providers (e.g.
`osv`). Ensure the relevant Cargo feature (e.g. `nvd` for NVD) is enabled when
building.

---

### Invalid config file path (-c)

**Message:** Error loading config via `-c /path/to/file`

**Cause:** File not found, permission denied, or invalid TOML.

**Remediation:** Ensure the path exists and is readable. Use an absolute path
or path relative to the current directory.

---

### Database permission or world-writable (SEC-014)

**Message:** Database file cannot be opened or is world-writable.

**Cause:** Cache or ignore DB file has overly permissive permissions.

**Remediation:** Fix file permissions: directories `0755`, files `0644`. Remove
world-writable bits. Do not use `0666` for DB files. Prefer XDG paths
(`~/.cache/verilyze`, `~/.local/share/verilyze`) over `/tmp` for
`--cache-db` and `--ignore-db`; `/tmp` is often world-writable.

---

## Reachability evidence

### No `evidence` or `advisory_symbols` in my JSON report

**Cause:** Symbol-level evidence requires `--reachability-mode best-available`
(or config/env equivalent). The default `tier-b` mode reports package-level
reachability only.

**Remediation:** Run `vlz scan --reachability-mode best-available`. Evidence
appears only when the CVE provider lists advisory symbols (mostly OSV-shaped
data) and your first-party source references them.

### What does `symbol_usage: not_found` mean?

**Meaning:** Under Tier C, the advisory listed symbols but no matching
first-party references were found with confident absence. This can support
staying on a pinned vulnerable version for symbol-specific risk, but other
exposure paths may still exist.

**Limits:** Matching is heuristic (imports, names), not data-flow proof.
Transitive or runtime-only exposure is not covered.

### SARIF shows manifest paths but no source line

**Cause:** No advisory symbols from the provider, no first-party symbol match,
reachability mode is not `best-available`, or declaration lines could not be
parsed for that dependency (e.g. `cargo metadata` / pip-freeze paths).

**Remediation:** Use `best-available`, ensure OSV provides symbol metadata, and
confirm your code references the listed symbols. When reachability evidence
exists, SARIF uses the consumer source line as `locations[0]` and declaration
lines (when known) or manifest paths in `relatedLocations`. When evidence is
absent but declaration lines were parsed, SARIF uses declaration `startLine` in
primary `locations`. `declarations[]` in JSON is separate from `evidence[]`:
declarations show where a dependency is declared, not where vulnerable code runs.

---

## Advisory ranges (FR-039)

### What is the Ranges column / `affected_ranges` field?

**Meaning:** When the CVE provider is OSV (or stores OSV-shaped `raw_vulns`),
`vlz` decodes `affected[].ranges` for the scanned package onto each CVE.
Plain and HTML reports show a **Ranges** summary (for example
`ECOSYSTEM introduced:0 fixed:1.2.3`). JSON and SARIF include structured
`affected_ranges`. CycloneDX/SPDX attach the same compact string as
`vlz:affected_ranges`. Offline cache hits still attach ranges by decoding
cached raw vulns.

**Limits:** Ranges are advisory metadata from OSV, not an auto-upgrade plan
and not a single "fix to this version" recommendation. Non-OSV providers may
omit ranges. Scan JSON/SARIF findings include a structured `upgrade_plan`
(FR-040) derived from those ranges; plain/HTML keep Ranges only. Applying upgrades uses `vlz fix` (FR-041): default writes lock updates for
supported strategies (npm / Cargo); `vlz fix --dry-run` previews without
writing.

### How do I use editor diagnostics?

Run `vlz lsp` from an editor Language Server configuration. It uses standard
input and output for JSON-RPC, so do not run it directly in an interactive
terminal. The server publishes diagnostics for vulnerable dependency
declarations and offers a non-writing **Show upgrade plan** Code Action.

Editor diagnostics never execute dependency code, even when the configuration
enables `allow_dependency_code_execution`. `vlz fix` modifies supported lock
files; use `vlz fix --dry-run` to preview changes. Folder trust and applying
an upgrade from an editor are planned separately.

---

## CVE providers

### Provider authentication

- **GitHub Advisory:** Optional. Use `GITHUB_TOKEN` (or `VLZ_GITHUB_TOKEN` to
  override) for higher rate limits. `GITHUB_TOKEN` is automatically set in
  GitHub Actions.
- **Sonatype OSS Index:** Required. Set `VLZ_SONATYPE_EMAIL` and
  `VLZ_SONATYPE_TOKEN` (create a free account at
  https://ossindex.sonatype.org).

### 401 Unauthorized from Sonatype

**Cause:** Missing or invalid credentials. Sonatype OSS Index requires
authentication.

**Remediation:** Set both `VLZ_SONATYPE_EMAIL` and `VLZ_SONATYPE_TOKEN`.
Verify the token is valid at https://ossindex.sonatype.org.

### Credential in error output

If you suspect a token or email was leaked in stderr: SEC-020 requires no
credential in error output. Report this as a security bug (see SECURITY.md).

### Why is NVD not available by default?

**Cause:** NVD (NIST National Vulnerability Database) is opt-in for several
reasons: (1) NVD enforces 5 requests per 30-second window for unauthenticated
use; vlz defaults to 10 parallel queries, so a cold-cache scan would exceed
the limit and trigger 429 backoff; (2) including NVD increases binary size
and dependencies (PRD Purpose & Scope, NFR-019); (3) PRD MOD-003 specifies
OSV-only as the default CVE provider.

**Remediation:** Build with `cargo install vlz --features nvd` if you need NVD.
See "How do I use NVD?" below.

---

### How do I use NVD?

**Steps:**

1. Build with the NVD feature: `cargo build --features nvd` or
   `cargo install vlz --features nvd`
2. Run a scan with NVD: `vlz scan --provider nvd`
3. For unauthenticated NVD use, lower `parallel_queries` (e.g. 2-3) via
   `--parallel 3` or config to avoid 429 rate-limit responses.

---

## Exit code 3 (Missing package manager)

### Required package manager not found

**Message:** `Required package manager not found on PATH for python (1 manifest(s) requiring it). Install via: apt-get install python3-pip (Debian/Ubuntu) or dnf install python3-pip (Fedora/RHEL).`

**Cause:** `--package-manager-required` is set, manifests were discovered for a
language that would invoke its package manager (no usable adjacent lock file),
and that package manager is not on PATH (FR-024).

**Remediation:** Install the package manager for your platform:
- **Debian/Ubuntu:** `apt-get install python3-pip` (Python) or
  `apt-get install ruby bundler` (Ruby)
- **Fedora/RHEL:** `dnf install python3-pip` (Python) or
  `dnf install ruby rubygem-bundler` (Ruby)
- **macOS:** `brew install python3` or `brew install ruby`
- **Windows:** Install Python from https://www.python.org/ and ensure pip is
  enabled; for Ruby use https://rubyinstaller.org/ and ensure `bundle` is on
  PATH.

Example for Ruby when Bundler is missing:

`Required package manager not found on PATH for ruby (1 manifest(s) requiring it). Install via: apt-get install ruby bundler (Debian/Ubuntu) or dnf install ruby rubygem-bundler (Fedora/RHEL).`

---

## Exit code 6 (Offline cache miss)

### CVE not found in cache, and unable to lookup CVE due to `--offline` argument

**Message:** `CVE not found in cache, and unable to lookup CVE due to
'--offline' argument.`

**Cause:** Scan found packages that need CVE lookups, but `--offline` blocks
network calls and the cache has no entries for them (FR-031).

**Remediation:** Either:
1. Run a scan without `--offline` once to populate the cache, then use
   `--offline`.
2. Use `vlz preload` to pre-populate the cache before an offline scan.
3. Remove `--offline` if network access is acceptable.

---

## Exit code 5 (CVE provider fetch failed)

### Unable to fetch CVE data from provider

**Message:** `Unable to fetch CVE data from provider. Run with -v for details.`

**Cause:** One or more CVE lookups failed after retries (network error, API
error, auth failure, etc.). The scan exits 5 instead of reporting "No
vulnerabilities found" to avoid false negatives (FR-010).

**Remediation:** Run with `-v` for detailed error output. Check network
connectivity, firewall, and provider-specific auth (e.g. VLZ_SONATYPE_EMAIL and
VLZ_SONATYPE_TOKEN for Sonatype). Verify the provider API is reachable. Retry
later if the failure was transient.

---

## Partial dependency resolution (FR-022, FR-022a, SEC-023)

### `vlz warning: Only direct dependencies were scanned for ...`

**Cause:** Transitive dependency resolution was not performed for the listed
manifest. Direct-only coverage is emitted only when explicitly permitted.
Common reasons:

- **`offline mode` or `benchmark mode`:** `--offline` and `--benchmark` skip
  package-manager network resolution (pip, `cargo metadata`, `go list`) (FR-031,
  FR-029).
- **`transitive resolution failed; direct-only fallback enabled`:** Transitive
  resolution was required but could not be completed; you opted in via
  `allow_direct_only_fallback`.

**Remediation (best):** Add an adjacent lock file for transitive coverage.
Prefer PEP 751 `pylock.toml` / `pylock.<name>.toml` (for example
`pylock.dev.toml`) for Python. See
[Appendix A -- Manifest and lock files](../architecture/PRD.md#appendix-a-manifest-and-lock-files)
for supported formats (`pylock.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`,
etc.).

**Optional (trusted workspaces only):** Enable executable pip resolution:

```sh
vlz scan --allow-dependency-code-execution /path/to/project
```

Or set `VLZ_ALLOW_DEPENDENCY_CODE_EXECUTION=1` or
`allow_dependency_code_execution = true` in config. This may run local project
code and third-party build hooks during resolution. See [SECURITY.md](../SECURITY.md).

**Plugin authors:** lock-first resolver order, empty-lock vs empty-project,
and CLI contract fixtures are in
[CONTRIBUTING -- Adding a new language plugin](../CONTRIBUTING.md#adding-a-new-language-plugin).

**Python project manifests without a lock:** All Python project manifests
(`requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.cfg`, `setup.py`)
**fail closed**: transitive resolution is required via an adjacent lock file,
safe `pip lock -r` (requirements.txt only, when pip >= 25.1), explicit
`--allow-dependency-code-execution`, or `--allow-direct-only-fallback`
(direct-only scan with FR-022a warning). Without those, the scan exits **4**
with the FR-022 message below. `pyproject.toml` / `setup.py` / `setup.cfg` /
`Pipfile` do not soft-default to direct-only. `--offline` / `--benchmark`
permit DirectOnly coverage (FR-022a) instead of exit 4.

**Rust without `Cargo.lock`:** `Cargo.toml` without an adjacent or workspace
`Cargo.lock` uses `cargo metadata` for transitive resolution when not in
offline or benchmark mode. Resolved versions reflect the latest compatible
crates at scan time with **default Cargo features only**; commit `Cargo.lock`
for reproducibility. If `cargo` is missing or metadata fails (registry or
network unavailable), the scan exits **4** unless
`--allow-direct-only-fallback` is set. Use `-v` to see the underlying cause
when `cargo` is present but resolution fails.

**Go `go.mod`:** Online transitive resolution uses `go list -m all`. When
`--offline` or `--benchmark` skips `go list`, or when `go` is not on PATH,
`vlz` reads pinned `module@version` identities from adjacent `go.sum`
(checksum set, not the `go list` build graph). If `go.sum` is missing,
unreadable, or has no pins, coverage is DirectOnly (offline/benchmark) or
exit **4** when `go` is missing / `go list` fails (unless
`--allow-direct-only-fallback` is set).

**JavaScript / TypeScript (`package.json`):** The `javascript` language covers
both JavaScript and TypeScript. Prefer an adjacent or parent workspace lock
(`package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, or
`bun.lock`). When multiple locks exist, one is chosen (not unioned) and a
warning is emitted. `--offline` / `--benchmark` still parse a committed lock
when present. Without a usable lock, the scan exits **4** by default
(SEC-023 does not run npm/yarn/pnpm/bun). Use
`--allow-dependency-code-execution` for ephemeral package-manager resolution,
or `--allow-direct-only-fallback` for direct-only coverage.

**Java / Kotlin (Maven and Gradle):** The `java` language covers both Java and
Kotlin source. Prefer an adjacent or parent `gradle.lockfile` for Gradle
projects. Maven `pom.xml` and Gradle version catalogs supply direct coordinates
only; without a Gradle lock or gated PM resolution, the scan exits **4** by
default (SEC-023 does not run mvn/gradle/gradlew). `--offline` / `--benchmark`
still parse `gradle.lockfile` when present. Use
`--allow-dependency-code-execution` for gated PM resolution in trusted
environments, or `--allow-direct-only-fallback` for direct-only coverage.

**Ruby (Bundler / RubyGems):** The `ruby` language covers Gemfile, gems.rb, and
`*.gemspec`. Prefer a pair-matched lock (`Gemfile.lock` or `gems.locked`; parent
walk up to the scan root). Without a usable lock, the scan exits **4** by
default (SEC-023 does not run `bundle`; `bundle lock` evaluates Gemfile as
Ruby). Use `--allow-dependency-code-execution` for ephemeral `bundle lock`, or
`--allow-direct-only-fallback` for direct-only coverage.

### Unable to detect transitive dependencies (exit 4)

**Message:** `Unable to detect transitive dependencies. Add an adjacent lock
file, use --allow-dependency-code-execution for full resolution in a trusted
environment, or pass --allow-direct-only-fallback to scan direct dependencies
only.`

**Cause:** Transitive resolution was required but could not be completed
(FR-022). Typical cases: any Python project manifest without a lock and without
a successful safe/exec path; `Cargo.toml` without `Cargo.lock` when
`cargo metadata` fails; `go.mod` when `go list -m all` fails or `go` is not
on PATH; `package.json` without an adjacent/parent lock file when package
manager execution is disabled; lock-less Java Maven/Gradle manifests without
`gradle.lockfile` when PM execution is disabled; lock-less Ruby Gemfile/gems.rb
or gemspec without Gemfile.lock/gems.locked when Bundler execution is disabled;
explicit pip resolution failed after
`--allow-dependency-code-execution`; or the parser found no dependencies.

**Remediation:**

1. Commit an adjacent lock file (preferred): PEP 751 `pylock.toml` /
   `pylock.<name>.toml` for Python, `Cargo.lock`, `go.sum` (with `go.mod`), or
   a JS lock (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`),
   or `gradle.lockfile` for Java/Gradle, or `Gemfile.lock` / `gems.locked` for
   Ruby.
2. Ensure pip >= 25.1 is on PATH for safe `pip lock -r` on `requirements.txt`.
3. For Rust lock-less scans, ensure `cargo` is on PATH and the crates.io
   registry is reachable (or use `--offline` with a committed `Cargo.lock`).
4. For Go module projects, ensure `go` is on PATH.
5. For JavaScript/TypeScript, commit a lock file or use
   `--allow-dependency-code-execution` only in trusted CI or workspaces.
6. For Java/Kotlin, commit `gradle.lockfile` for Gradle projects or use
   `--allow-dependency-code-execution` only in trusted CI or workspaces.
7. For Ruby, commit `Gemfile.lock` / `gems.locked` or use
   `--allow-dependency-code-execution` only in trusted CI or workspaces
   (`bundle lock` evaluates Gemfile as Ruby).
8. For local Python projects, use `--allow-dependency-code-execution` only in
   trusted CI or workspaces (see SECURITY.md).
9. When you accept direct-only scanning without transitive coverage, use
   `--allow-direct-only-fallback`, `VLZ_ALLOW_DIRECT_ONLY_FALLBACK=1`, or
   `allow_direct_only_fallback = true` in config.
10. Use `--offline` or `--benchmark` only when you accept direct-only scanning
   (warnings will be emitted for affected manifests).

See also `man vlz` for configuration keys `keep_ephemeral_venv`,
`allow_dependency_code_execution`, `allow_direct_only_fallback`, and
`fail_fast`.

---

## Standalone Python lock files

### Scanning a directory with only `pylock.toml` (or other lock files)

**Cause:** Previously, lock files were only used when adjacent to a manifest.
Directories containing only `pylock.toml`, `poetry.lock`, `uv.lock`, or
`Pipfile.lock` were not discovered as entry points.

**Behavior:** Supported lock files in a directory with no Python manifest
(`requirements.txt`, `pyproject.toml`, etc.) are now discovered and scanned
directly. A valid lock with zero packages completes with `scanned_transitive`
and exit 0 when no CVEs are found.

### Multiple lock files in one directory

**Behavior:** When more than one supported lock file exists in the same
directory, `vlz` parses **all** of them and unions packages (orphan locks as
separate entry points; adjacent locks merged during manifest resolution). A
warning is emitted:

`vlz warning: Multiple lock files in <dir> were scanned and packages merged: ...`

**Operational note:** Stale or duplicate lock files in one directory can cause
extra packages to appear in results. Prefer keeping one canonical lock file per
project directory, or scope with `--lock-file` / `python.lock_files` /
`VLZ_PYTHON_LOCK_FILES` (union applies among listed locks only).

### Lock-file allowlist (`--lock-file`)

Repeat `--lock-file` or set `python.lock_files` in config (comma-separated via
`VLZ_PYTHON_LOCK_FILES`) to discover and merge **only** the listed lock
basenames. When a directory already contains lock files but a listed file is
missing, the scan exits **2** (user-recoverable). Unset allowlist keeps Phase 1
behavior: union all supported locks in each directory.

```sh
vlz scan --lock-file poetry.lock .
vlz scan --lock-file pylock.toml --lock-file poetry.lock .
```

### `manifest_paths` with lock files

When packages come from an adjacent lock file, JSON/SARIF `manifest_paths` on
each finding list the **lock file path** (for example `pylock.toml`), not the
manifest entry point. When a package appears in multiple merged locks, all
source lock paths are listed. `manifest_paths` is per package version, not per
CVE.

---

## Multi-manifest scans (FR-037)

When `vlz scan` discovers multiple manifests under a root directory, each
manifest is parsed and resolved independently. Successfully resolved manifests
contribute packages to the CVE lookup phase even when other manifests fail.

**Report metadata:** JSON, SARIF, HTML, and plain-text reports include a
`manifest_coverage` array listing each manifest path, scan status
(`scanned_transitive`, `scanned_direct_only`, `failed_parse`,
`failed_resolution`), and error detail when applicable.

**Exit code 2:** If any manifest requires transitive resolution and cannot be
satisfied (or cannot be parsed), the scan exits **2** after rendering the report
for manifests that succeeded. A consolidated summary on stderr lists all failed
manifests at the end of the run (easy to find in CI logs).

**`--fail-fast`:** Stops manifest processing on the first blocking parse or
resolution failure and skips CVE lookup. Applies only to manifest
discovery/parsing/resolution; CVE provider fetch behavior is unchanged. Use for
strict CI jobs that should abort early. Set via `--fail-fast`, `fail_fast = true`
in config, or `VLZ_FAIL_FAST=1`.

---

## Network and TLS errors

### TLS / certificate verification failed

**Message:** Network or TLS-related errors when querying the CVE provider.

**Cause:** Server certificate invalid, expired, or hostname mismatch (NFR-004,
SEC-002).

**Remediation:** Update system CA certificates. On Debian/Ubuntu:
`apt-get install ca-certificates`. Do not disable TLS verification unless you
understand the security implications.

---

### Network error (transient)

**Message:** `Network error` or `Transient error` (with optional `Caused by:`
in verbose mode)

**Cause:** Connection failed, timeout, or HTTP error (e.g. 429, 5xx). Network
errors are often transient (NFR-018).

**Remediation:** The client automatically retries with exponential backoff on
transient errors (NFR-005, SEC-007). If retries are exhausted, run the command
again. Use `--backoff-base`, `--backoff-max`, and `--max-retries` to tune
retry behavior. Check connectivity and firewall settings. Use `-v` for more
detail.

---

## Database integrity

### Database integrity check failed

**Message:** `vlz db verify` reports failure or "Database integrity check
failed".

**Cause:** Cache or ignore DB was modified or corrupted (SEC-004).

**Remediation:** Remove the affected `.redb` file and re-run a scan to rebuild
the cache. Back up important false-positive markings before removing the ignore
DB.

---

## Verbose output and sensitive data

**Guidance:** Verbose mode (`-v` or `--verbose`) prints additional diagnostic
information, including cause chains and internal paths. This output may contain
sensitive information (NFR-018, SEC-020, DOC-010).

**Remediation:** Redact paths, user names, and any internal details before
sharing verbose output in bug reports or public channels.
