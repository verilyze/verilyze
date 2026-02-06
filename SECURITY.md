# Security

## Reporting vulnerabilities

If you believe you have found a security vulnerability, please report it responsibly.

- **Preferred:** Contact the maintainers via a private channel (e.g. GPG-encrypted email) if you have their contact details. Do not open a public issue for unfixed security bugs.
- **Otherwise:** Open a private security advisory in the repository (e.g. GitHub Security Advisories) so maintainers can triage and respond.

Please include:

- Description of the issue and steps to reproduce.
- Impact (e.g. privilege escalation, data exposure).
- Any suggested mitigations or patches.

We will acknowledge receipt and work with you on a fix and disclosure timeline.

## Threat model and compliance

- The project maintains a **threat model** (see [architecture/PRD.md](architecture/PRD.md) SEC-001 and Risk & Threat Model).
- Security requirements (SEC-*), TLS, integrity checks, and least-privilege are described in the PRD.
- A **compliance checklist** (e.g. COMPLIANCE.md) may be present for SOC 2 / ISO 27001 / CMMC mapping; refer to the PRD (SEC-010, DOC-008) and repository root for the latest location.

## For users

- Run `spd` with the minimum privileges needed (no set-UID; it runs as the invoking user).
- Use `spd db verify` to check integrity of cached data (SHA-256 by default).
- Keep the tool and dependencies updated; run `spd scan` on this repository (dogfooding, SEC-015) as part of your workflow.
