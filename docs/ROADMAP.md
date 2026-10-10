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
| W3-1 | Matching transparency report (structured matching/explain fields per finding) | done | |
| W3-2 | Suppression expiry (`expires_at`) and path-scoped false positives | done | |
| W3-3 | PURL qualifier fidelity on SBOM consume | done | |
| W4-1 | Guided remediation ROI; PHP and NuGet remediators; pylock apply if practical | done | Composer + NuGet + pylock in-place apply |
| W4-2 | Polyglot Tier D (Java/Kotlin, Ruby, PHP, .NET); keep capabilities matrix accurate | done | Tier D on by default (like JS) |
| W4-3 | Airgap corpus authenticity (`vlz db import` signature / cosign-verify path) | done | `--cosign-bundle` / `--signature` + fail closed |
| W4-4 | Signed VEX verification scheme (FR-049) | done | sibling / `--vex-cosign-bundle`; default unsigned still allowed |
| W4-5 | GHSA docs only: how to add `github` to `--providers` when a token is set; keep OSV default | done | FAQ |
| W4-6 | Forge recipes that apply `vlz fix --format diff` (no GitHub App) | done | examples/ GitHub + GitLab |
| HC-1 | Opt-in license policy (needs PRD Purpose and Scope amendment first) | later | |
| HC-2 | Dedicated `vlz export-sbom` (MOD-008) | done | |
| HC-3 | KEV to OpenVEX `exploited` (FR-048) | done | |
| HC-4 | SQLite DB backend | later | |
| HC-5 | Container image SLSA only (SEC-021); still no image CVE scan | done | |
| HC-6 | Reproducible release binaries (NFR-006) | done | |
| HC-7 | Optional FIPS-204 cache signatures (SEC-005) | later | |
| HC-8 | Marketplace editor clients (sibling repo) | later | |
| HC-9 | More ecosystems only with lock-first + OSV coverage | done | Dart/Pub (`vlz-dart`) |
| HC-10 | NuGet residual depth (orphan locks, restore edge cases); `Directory.Packages.props` version fill already ships | done | orphan packages.lock.json; ephemeral restore copies Directory.Packages.props |
| HC-11 | Optional CONTRIBUTING split if TOC/matrix still leave it unusable | later | |
| HC-12 | Install the real Dart/Flutter SDK in the Cursor Cloud Agent image (`.cursor/Dockerfile`) and document it as a general dev prerequisite, so `DartRemediator` (`pub add`) and Dart scans can be tested against real binaries | planned | HC-9 remediator was only tested with stub binaries |
| HC-13 | Restore openSUSE Tumbleweed RPM builds: lower MSRV to the Rust that enabled distro targets ship (1.98 if the workspace builds and tests on 1.98.x), re-enable the target, ship a patch release. Never move a published tag | in progress | MSRV 1.98 and Tumbleweed re-enabled on this branch; done after the patch release ships |
| HC-14 | MSRV policy: `rust-toolchain.toml` (dev/CI toolchain) is decoupled from `rust-version` (MSRV); the toolchain may lead the MSRV but never trail it; MSRV rises only for a code or dependency reason after the distro gate passes | done | `scripts/crates_publish.py`; CONTRIBUTING "Rust toolchain and MSRV policy" |
| HC-15 | Single-source packaging: `packaging/obs/distro-rust.toml` lists per-distro Rust floors; RPM spec `BuildRequires` are derived from `rust-version` instead of hand-edited literals | done | `scripts/distro_rust.py`; `sync_rpm_specs.py` |
| HC-16 | Distro Rust availability gate (`make check-distro-rust`) in `check-fast` and `release-preflight.sh`, so an unbuildable target blocks before the tag, not after | done | offline data check plus optional live container probe |
| HC-17 | CI MSRV job (check with exactly `rust-version`) and MSRV-aware resolver v3 so dependency updates cannot raise the floor silently | done | |
| HC-18 | Distro container build matrix (PR path filter plus nightly) building with distro-packaged `rust`/`cargo` and `--locked` | done | `.github/workflows/distro-build.yml` |
| HC-19 | Renovate: toolchain bumps never edit `rust-version`; MSRV changes need a deliberate PR and never automerge | done | `renovate.json` |
| HC-20 | Docs and agent guidance for the MSRV / distro policy (README, INSTALL, CONTRIBUTING, PRD, AGENTS, rules, skills) and an `ai-learnings` entry | done | |

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
