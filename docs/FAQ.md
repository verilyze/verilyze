<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# FAQ and Troubleshooting (DOC-010)

Common error messages and suggested remediation steps. See also
[architecture/PRD.md](../architecture/PRD.md) for requirements, and
[README.md](../README.md) for configuration and exit codes.

---

## Docker

### Docker cache files owned by root

**Cause:** The container runs as root by default. When you mount
`~/.cache/verilyze` for persistent cache, files created inside the
container are owned by root on the host.

**Remediation:** Use `--user "$(id -u):$(id -g)"` so the container runs
as your user. Ensure the cache directory exists before the first run:
`mkdir -p ~/.cache/verilyze`. See [README -- Running with
Docker](../README.md#running-with-docker).

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

**Message:** `Required package manager not found on PATH. Install via: apt-get
install python3-pip (Debian/Ubuntu) or dnf install python3-pip (Fedora/RHEL).`

**Cause:** `--package-manager-required` is set but pip (or the language’s
package manager) is not on PATH (FR-024).

**Remediation:** Install the package manager for your platform:
- **Debian/Ubuntu:** `apt-get install python3-pip`
- **Fedora/RHEL:** `dnf install python3-pip`
- **macOS:** `brew install python3`
- **Windows:** Install Python from https://www.python.org/ and ensure pip is
  enabled.

---

## Exit code 4 (Offline cache miss)

### CVE not found in cache, and unable to lookup CVE due to `--offline` argument

**Message:** `CVE not found in cache, and unable to lookup CVE due to
'--offline' argument.`

**Cause:** Scan found packages that need CVE lookups, but `--offline` blocks
network calls and the cache has no entries for them (FR-031).

**Remediation:** Either:
1. Run a scan without `--offline` once to populate the cache, then use
   `--offline`.
2. Use `vlz preload` (when implemented) to pre-populate the cache.
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
manifest. Common reasons:

- **`offline mode` or `benchmark mode`:** `--offline` and `--benchmark` skip pip
  network resolution (FR-031, FR-029).
- **`executable dependency resolution is disabled`:** Secure default (SEC-023).
  `vlz` does not run `pip install` or `pip lock -e` on local projects unless
  you opt in.
- **`transitive resolution unavailable`:** No adjacent lock file and pip is not
  on PATH for a local project manifest (`setup.py`, `pyproject.toml`, etc.).
- **`transitive resolution failed; direct-only fallback enabled`:** Transitive
  resolution was required but could not be completed; you opted in via
  `allow_direct_only_fallback`.

**Remediation (best):** Add an adjacent lock file for transitive coverage. See
[Appendix A -- Manifest and lock files](../architecture/PRD.md#appendix-a-manifest-and-lock-files)
for supported formats (`poetry.lock`, `Pipfile.lock`, `pylock.toml`, etc.).

**Optional (trusted workspaces only):** Enable executable pip resolution:

```sh
vlz scan --allow-dependency-code-execution /path/to/project
```

Or set `VLZ_ALLOW_DEPENDENCY_CODE_EXECUTION=1` or
`allow_dependency_code_execution = true` in config. This may run local project
code and third-party build hooks during resolution. See [SECURITY.md](../SECURITY.md).

**Requirements files without pip:** `requirements.txt` requires transitive
resolution via lock file, safe `pip lock` (when pip >= 25.1), explicit
opt-in pip fallback, or `--allow-direct-only-fallback` (direct-only scan with
FR-022a warning). Without those, the scan exits **2** with the FR-022 message
below.

### Unable to detect transitive dependencies (exit 2)

**Message:** `Unable to detect transitive dependencies. Try installing the
package manager or generate a lock file before running vlz.`

**Cause:** Transitive resolution was required but could not be completed
(FR-022). Typical cases: `requirements.txt` or `Pipfile` without a lock file
and without working pip resolution; explicit pip resolution failed after
`--allow-dependency-code-execution`; or the parser found no dependencies.

**Remediation:**

1. Commit an adjacent lock file (preferred).
2. Ensure pip >= 25.1 is on PATH for safe `pip lock -r` on `requirements.txt`.
3. For local projects, use `--allow-dependency-code-execution` only in trusted
   CI or workspaces (see SECURITY.md).
4. When you accept direct-only scanning without transitive coverage, use
   `--allow-direct-only-fallback`, `VLZ_ALLOW_DIRECT_ONLY_FALLBACK=1`, or
   `allow_direct_only_fallback = true` in config.
5. Use `--offline` or `--benchmark` only when you accept direct-only scanning
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
project directory. Future releases may add `--lock-file` allowlist scoping.

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
