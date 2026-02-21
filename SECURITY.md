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
- **Compliance checklist:** [COMPLIANCE.md](COMPLIANCE.md) in the repository
  root maps controls to implementation (SOC 2 / ISO 27001 / CMMC); refer to the
  PRD (SEC-010, DOC-008) for requirements.

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
- Use `vlz db verify` to check integrity of cached data (SHA-256 by default).
- Keep the tool and dependencies updated; run `vlz scan` on this repository
  (dogfooding, SEC-015) as part of your workflow.
