<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# FAQ and Troubleshooting (DOC-010)

Common error messages and suggested remediation steps. See also
[architecture/PRD.md](../architecture/PRD.md) for requirements, and
[README.md](../README.md) for configuration and exit codes.

---

## Exit code 2 (Misconfiguration)

### Invalid TOML in configuration file

**Message:** `Invalid TOML in configuration file
~/.config/super-duper/super-duper.conf: ...`

**Cause:** The configuration file contains syntax that is not valid TOML.

**Remediation:** Fix the TOML syntax. Common issues: unclosed quotes, trailing
commas, invalid escape sequences. Use a TOML validator or check the
[TOML spec](https://toml.io/).

---

### Unknown configuration key

**Message:** `Unknown configuration key 'foo' (from user)`

**Cause:** A key in the config file is not recognized (SEC-006).

**Remediation:** Remove the unknown key or fix the key name. Run
`spd config --list` to see supported keys. For per-language regex patterns, use
`[python].regex` (see FR-006).

---

### Parallel queries too high

**Message:** `Parallel queries must be at most 50; got 51`

**Cause:** `--parallel` or `SPD_PARALLEL_QUERIES` exceeds the maximum (FR-012).

**Remediation:** Use a value ≤ 50, e.g. `spd scan --parallel 50` or
`export SPD_PARALLEL_QUERIES=50`.

---

### Unknown provider

**Message:** `Unknown provider: foo (use 'spd db list-providers' to list)`

**Cause:** `--provider` names a provider that is not registered (FR-019).

**Remediation:** Run `spd db list-providers` to see available providers (e.g.
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
world-writable bits. Do not use `0666` for DB files.

---

## CVE providers

### Provider authentication

- **GitHub Advisory:** Optional. Use `GITHUB_TOKEN` (or `SPD_GITHUB_TOKEN` to
  override) for higher rate limits. `GITHUB_TOKEN` is automatically set in
  GitHub Actions.
- **Sonatype OSS Index:** Required. Set `SPD_SONATYPE_EMAIL` and
  `SPD_SONATYPE_TOKEN` (create a free account at
  https://ossindex.sonatype.org).

### 401 Unauthorized from Sonatype

**Cause:** Missing or invalid credentials. Sonatype OSS Index requires
authentication.

**Remediation:** Set both `SPD_SONATYPE_EMAIL` and `SPD_SONATYPE_TOKEN`.
Verify the token is valid at https://ossindex.sonatype.org.

### Credential in error output

If you suspect a token or email was leaked in stderr: SEC-020 requires no
credential in error output. Report this as a security bug (see SECURITY.md).

### Why is NVD not available by default?

**Cause:** NVD (NIST National Vulnerability Database) is opt-in for several
reasons: (1) NVD enforces 5 requests per 30-second window for unauthenticated
use; spd defaults to 10 parallel queries, so a cold-cache scan would exceed
the limit and trigger 429 backoff; (2) including NVD increases binary size
and dependencies (PRD Purpose & Scope, NFR-019); (3) PRD MOD-003 specifies
OSV-only as the default CVE provider.

**Remediation:** Build with `cargo install spd --features nvd` if you need NVD.
See "How do I use NVD?" below.

---

### How do I use NVD?

**Steps:**

1. Build with the NVD feature: `cargo build --features nvd` or
   `cargo install spd --features nvd`
2. Run a scan with NVD: `spd scan --provider nvd`
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
2. Use `spd preload` (when implemented) to pre-populate the cache.
3. Remove `--offline` if network access is acceptable.

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

**Message:** `spd db verify` reports failure or "Database integrity check
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
