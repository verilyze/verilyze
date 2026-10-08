<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Product roadmap

verilyze stays a **lock-first CVE SCA CLI**: fail closed, prefer locks over
executing project code, and ship SBOM/VEX without a hosted platform. This
file is the single product backlog. Do not mirror Must lists into the PRD,
a GitHub Project, or a batch of tracking issues.

## How to update status

The pull request that implements an ID sets **Status** to `done` (or
`in progress` while that PR is open). When behavior changes, update the FAQ,
[capabilities.md](capabilities.md), report schema, and CHANGELOG in the same
PR. The optional **Issue** column stays empty unless a human pastes a link;
agents do not open issues to fill it.

Status values: `done`, `in progress`, `planned`, `later`.

## Shipped (waves 1-2)

- Airgap CVE corpus import (`vlz db import`)
- Versioned GitHub Action and refreshed GHA sample
- PHP Composer language plugin
- Opt-in reachability CI gate (`exit_on_reachable`)
- `vlz fix --format diff`
- OSV `MAL-*` as `finding_class: malicious`
- GitLab CI sample
- NuGet / .NET language plugin
- JavaScript Tier D reachability
- VEX consume (FR-049)

## Open items

| ID | Item | Status | Issue |
|----|------|--------|-------|
| W3-1 | Matching transparency report (structured matching/explain fields per finding) | planned | |
| W3-2 | Suppression expiry (`expires_at`) and path-scoped false positives | planned | |
| W3-3 | PURL qualifier fidelity on SBOM consume | planned | |
| W4-1 | Guided remediation ROI; PHP and NuGet remediators; pylock apply if practical | planned | |
| W4-2 | Polyglot Tier D (Java/Kotlin, Ruby, PHP, .NET); keep capabilities matrix accurate | planned | |
| W4-3 | Airgap corpus authenticity (`vlz db import` signature / cosign-verify path) | planned | |
| W4-4 | Signed VEX verification scheme (FR-049) | planned | |
| W4-5 | GHSA docs only: how to add `github` to `--providers` when a token is set; keep OSV default | planned | |
| W4-6 | Forge recipes that apply `vlz fix --format diff` (no GitHub App) | planned | |
| HC-1 | Opt-in license policy (needs PRD Purpose and Scope amendment first) | later | |
| HC-2 | Dedicated `vlz export-sbom` (MOD-008) | later | |
| HC-3 | KEV to OpenVEX `exploited` (FR-048) | later | |
| HC-4 | SQLite DB backend | later | |
| HC-5 | Container image SLSA only (SEC-021); still no image CVE scan | later | |
| HC-6 | Reproducible release binaries (NFR-006) | later | |
| HC-7 | Optional FIPS-204 cache signatures (SEC-005) | later | |
| HC-8 | Marketplace editor clients (sibling repo) | later | |
| HC-9 | More ecosystems only with lock-first + OSV coverage | later | |
| HC-10 | NuGet residual depth (orphan locks, restore edge cases); `Directory.Packages.props` version fill already ships | later | |
| HC-11 | Optional CONTRIBUTING split if TOC/matrix still leave it unusable | later | |

## Non-goals

- Container, OS package, IaC, or secret scanning as product features
- Hosted dashboards, assignment desks, or SaaS governance UI
- Dependabot-style auto-PR bot as a first-party service
- Socket-style behavioral install-time malware analysis
- Default enabling of package-manager code execution (SEC-023)
- Using reachability to suppress findings by default (list + opt-in
  `exit_on_reachable` stays)

See also [architecture/PRD.md](../architecture/PRD.md) Appendix B (pointer
only) and [COMPLIANCE.md](../COMPLIANCE.md) Gaps.
