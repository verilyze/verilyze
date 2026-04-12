<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Security

## Reporting vulnerabilities

If you believe you have found a security vulnerability, please report it responsibly.

- **Preferred:** Contact the maintainers via a private channel (e.g.
  GPG-encrypted email) if you have their contact details. Do not open a public
  issue for unfixed security bugs.
- **Otherwise:** Open a private security advisory in the repository (e.g.
  GitHub Security Advisories) so maintainers can triage and respond.

Please include:

- Description of the issue and steps to reproduce.
- Impact (e.g. privilege escalation, data exposure).
- Any suggested mitigations or patches.

We will acknowledge receipt and work with you on a fix and disclosure timeline.

## Maintainer response expectations

These expectations support the
[OpenSSF Best Practices](https://bestpractices.dev/en/criteria/0) criteria
`vulnerability_report_response` and healthy interaction with reporters.

- **Security reports:** Maintainers aim to send an **initial response** (not
  necessarily a fix) within **14 days** of a good-faith private report.
- **Public bug reports (GitHub Issues):** Maintainers aim to **acknowledge** a
  majority of new issues so reporters know the report was seen; follow-up may
  take longer depending on capacity.

If you report a security issue and receive no reply within 14 days, consider a
polite follow-up on the same private channel.

## TLS and HTTPS (CVE providers)

Outbound HTTPS to CVE data sources (OSV, NVD, GitHub Advisory, Sonatype OSS Index)
uses **reqwest** with **rustls** (via hyper-rustls). Trust anchors follow the
**webpki** / Mozilla root program style (bundled root store, e.g. webpki-root-certs
class crates). The **ring** crate supplies rustls **cryptographic primitives** only;
**rustls** implements the TLS **protocol**. This is not the same as shipping
**BoringSSL** or **OpenSSL** as the application TLS stack; **OpenSSL is not linked**
into the default binary, which supports static musl builds (FR-025).

- **Protocol:** CVE provider HTTP clients set **minimum and maximum TLS to 1.3**
  (`reqwest` `tls_version_min` / `tls_version_max`). Only TLS 1.3 is offered in the
  handshake. Upstream crates may still compile TLS 1.2 code paths for the rustls
  stack; those paths are not used for these connections. If an enterprise TLS
  inspection proxy or path supports **only TLS 1.2**, HTTPS fetches may fail until
  the path supports TLS 1.3 or the policy is changed deliberately in code.
- **Cipher suites (TLS 1.3):** The process default **rustls** `CryptoProvider` limits
  client-offered suites to **`TLS_AES_256_GCM_SHA384`** and
  **`TLS_AES_128_GCM_SHA256`** (NIST SP 800-52 Rev. 2 §3.3.1.2). **`TLS_CHACHA20_POLY1305_SHA256`**
  is **not** offered. **CCM** suites from that NIST subsection are not enabled in this
  **ring** configuration (not implemented in the default rustls *ring* provider set
  used here). This is **not** a FIPS 140 validation claim; see below.
- **Verification:** Server certificates and hostnames are **always validated**. There
  is **no** CLI switch to disable TLS verification (SEC-002, NFR-004, OP-010).
- **Revocation (SEC-021):** **Windows** and **macOS** use **rustls-platform-verifier**, which
  delegates trust and revocation checks to the OS where applicable. **Linux** uses a **webpki**
  verifier path by default **without** automatic CRL fetching from issuer CDP URLs in this
  release. Operators who need CRL enforcement on Linux MAY set **tls_crl_bundle** (TOML),
  **VLZ_TLS_CRL_BUNDLE**, or **--tls-crl-bundle** to a PEM file of CRLs; the client then builds
  trust from the **OS PEM trust store** (`rustls-native-certs`) and checks the supplied CRLs
  with **rustls** / **webpki** (`reqwest` `tls_certs_only` + `tls_crls_only`). This is **not**
  a substitute for organizational PKI policy: CRLs MUST cover issuing CAs for every CVE
  provider endpoint you use, MUST be kept **fresh**, and stale CRLs cause false positives
  (valid servers rejected). **Non-goals for phase 1:** automatic fetch of CDP or OCSP URIs,
  caching policies for fetched revocation objects, and uniform cross-OS behavior when the
  Linux CRL path is enabled (other platforms still ignore the CRL file and use the platform
  verifier).
- **Timeouts:** CVE provider HTTP clients use connect and total request timeouts
  (defaults in `vlz-cve-client` as `DEFAULT_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS`
  and `DEFAULT_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS`) to limit hung connections and
  slow responses. Users can tune them via config file keys
  **provider_http_connect_timeout_secs** / **provider_http_request_timeout_secs**,
  env **VLZ_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS** /
  **VLZ_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS**, and scan-only flags
  **--provider-http-connect-timeout-secs** /
  **--provider-http-request-timeout-secs** (OP-010, CFG-005, CFG-006).
- **Licensing and dependency policy:** Third-party licenses must remain compatible
  with **GPL-3.0-or-later**; CI runs `make -j check`, which includes
  `cargo deny check` via `deny-check` (NFR-009, SEC-012). See
  [docs/LICENSING.md](docs/LICENSING.md).
  **TLS crypto** for CVE providers is **rustls** with the ***ring* crypto provider** only.

## Optional provider credentials

GitHub Advisory and Sonatype OSS Index CVE providers support optional or
required authentication via environment variables:

- **GitHub:** Optional. Set `GITHUB_TOKEN` (or `VLZ_GITHUB_TOKEN` to override)
  for higher rate limits. `GITHUB_TOKEN` is automatically set in GitHub Actions.
- **Sonatype:** Required. Set `VLZ_SONATYPE_EMAIL` and `VLZ_SONATYPE_TOKEN`
  (create a free account at https://ossindex.sonatype.org).

Credentials are read from the process environment only; they are never
stored in config files or on disk. Error messages and verbose output must
never contain tokens or emails; SEC-020 and tests enforce this. Users should
set env vars only in secure contexts (e.g. CI secrets, not shared terminals).
See [architecture/PRD.md -- Risk & Threat Model (section 11)](architecture/PRD.md#risk-threat-model)
and [COMPLIANCE.md](COMPLIANCE.md) for credential-handling controls.

## Threat model and compliance

- **Threat model:** The project maintains a threat model using the PASTA
  method, including security objectives, assets, threats, mitigations, and an
  ASCII attack tree. See
  [architecture/PRD.md -- Risk & Threat Model (section 11)](architecture/PRD.md#risk-threat-model)
  and SEC-001 in the PRD.
- Security requirements (SEC-*), TLS, integrity checks, and least-privilege are described in the PRD.
- **CI script inputs (merge queue and release):** PRD **OP-019**. Shell scripts
  `scripts/check-dco.sh`, `scripts/check-signatures.sh`, and
  `scripts/extract-changelog-for-release.sh` apply allow-listed validation for
  values supplied from GitHub Actions in those flows; shared logic lives under
  `scripts/lib/`.
- **Compliance checklist:** [COMPLIANCE.md](COMPLIANCE.md) in the repository
  root maps controls to implementation (SOC 2 / ISO 27001 / CMMC); refer to the
  PRD (SEC-010, DOC-008) for requirements.

## Regular expressions (ReDoS)

User-configurable regex patterns (FR-006, e.g. `[python].regex`) are used for
manifest discovery. SEC-022 requires that regex usage does not suffer from
catastrophic backtracking. The project uses the Rust `regex` crate, which
implements finite automata and guarantees linear-time matching. The dependency
must remain at regex >= 1.5.5 (CVE-2022-24713 fix). When adding new regex
usage, ensure the engine or validation satisfies SEC-022.

## Temporary file security

- **Ephemeral temp creation:** The program uses the `tempfile` crate for
  atomic creation (mkstemp-style O_EXCL) and cryptographically random names,
  mitigating symlink and predictable-name attacks (SEC-013).
- **Ephemeral venvs (FR-023):** When the pip fallback resolver creates
  ephemeral virtual environments, it prefers `XDG_RUNTIME_DIR` or `TMPDIR`
  when set (per-user, not world-writable); otherwise falls back to
  `std::env::temp_dir()`. Directories are created with `0o700` on Unix.
- **SEC-014:** The program refuses to use cache or ignore DB files that are
  world-writable. Using `--cache-db /tmp/foo.redb` or similar is allowed
  but will fail with a clear error if the file exists with overly permissive
  permissions.
- **`/tmp` usage:** `/tmp` is acceptable when creation is secure (atomic
  creation, random names). The program does not avoid `/tmp` entirely but
  uses it only with these patterns.

## Test results and dogfooding (SEC-018)

- **Fuzz testing:** AFL fuzz targets in `tests/fuzz/` cover config TOML, all
  manifest and lock file formats (see [Appendix
  A](architecture/PRD.md#appendix-a-manifest-and-lock-files)), and CLI
  argument value parsing (`config --set`) (NFR-020, SEC-017). Run `make fuzz` or
  `./scripts/fuzz.sh` (requires cargo-afl and AFL++). Results and coverage can
  be linked here or from CI artifacts when available.
- **Latest `vlz scan` (dogfooding):** SEC-015 requires the project to be
  scannable by the latest stable verilyze with exit 0. When CI or release
  artifacts include a latest-scan report, it will be linked here (e.g. from the
  repository Releases or a dedicated docs path).

## For users

- Run `vlz` with the minimum privileges needed (no set-UID; it runs as the
  invoking user).
- Release binaries are stripped of symbols (NFR-023) to reduce
  information disclosure and binary size.
- Use `vlz db verify` to check integrity of cached data (SHA-256 by default).
- Keep the tool and dependencies updated; run `vlz scan` on this repository
  (dogfooding, SEC-015) as part of your workflow.
