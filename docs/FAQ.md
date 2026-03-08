<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# FAQ and Troubleshooting (DOC-010)

Common error messages and suggested remediation steps. See also
[architecture/PRD.md](../architecture/PRD.md) for requirements, and
[README.md](../README.md) for configuration and exit codes.

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
world-writable bits. Do not use `0666` for DB files.

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
