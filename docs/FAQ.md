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
`osv`). Ensure the relevant Cargo feature (e.g. OSV) is enabled.

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

**Message:** `Network error` (with optional `Caused by:` in verbose mode)

**Cause:** Connection failed, timeout, or HTTP error (e.g. 429, 5xx). Network
errors are often transient (NFR-018).

**Remediation:** Retry the command. Check connectivity and firewall settings.
If the provider returns 429 (rate limit), wait and retry. Use `-v` for more
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
