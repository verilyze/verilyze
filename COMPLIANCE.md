<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Compliance overview

This document maps verilyze security and operational controls to baseline
expectations from SOC 2, ISO 27001, and CMMC. It supports SEC-010 and DOC-008.
It is **not** a certification or audit attestation.

## Purpose and scope

- **In scope:** The `vlz` CLI, its dependencies, CI/CD, release artifacts, and
  repository supply-chain evidence.
- **Out of scope:** Customer environments, operator PKI policy beyond documented
  TLS/CRL options, and formal third-party audits (see Reviewer sign-off).

## Control matrix

| Control area | Standard refs | PRD IDs | Implementation evidence |
|--------------|---------------|---------|-------------------------|
| Dependency inventory (SBOM) | NTIA minimum elements | SEC-019 | [sbom/v1/](sbom/v1/), `make generate-sbom`, `make check-sbom`, [.github/workflows/supply-chain.yml](.github/workflows/supply-chain.yml) `sbom` job |
| Vulnerability monitoring | SOC 2 CC7, ISO 27001 A.12 | SEC-015, SEC-016 | `dogfood` job in supply-chain workflow, `make deny-check`, [deny.toml](deny.toml), [CodeQL](.github/workflows/codeql.yml) |
| License compliance | SOC 2 CC9 | SEC-012, DOC-012 | `make deny-check`, [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES), REUSE (`make check-headers`) |
| Secure communications | ISO 27001 A.13, CMMC SC | SEC-002, NFR-004, SEC-024 | [vlz-cve-client](crates/core/vlz-cve-client/) TLS 1.3 + cert validation; optional Linux CRL bundle |
| Credential handling | SOC 2 CC6 | SEC-008, SEC-020 | Env-only provider tokens; no secrets in logs/errors |
| Data protection (local cache) | SOC 2 CC6, CMMC MP | SEC-014, OP-003 | XDG cache paths, restrictive DB permissions, `vlz db verify` |
| Auditability | SOC 2 CC7 | SEC-009, NFR-013, FR-010 | Deterministic exit codes; stderr diagnostics; dogfood JSON/SARIF artifacts |
| Least privilege | CMMC AC, SEC-003 | OP-001 | No set-UID; runs as invoking user |
| Release integrity | Supply chain best practice | SEC-021 | [release.yml](.github/workflows/release.yml) SLSA L3 binary provenance via `slsa-github-generator` v2.1.0; Cosign signing for all assets |
| Input validation | CMMC SI, SEC-017 | NFR-020 | AFL fuzz targets (`make fuzz`), strict config parsing (SEC-006) |
| JSON report contract | Interoperability | DOC-005, NFR-014 | [schemas/v1/report.json](schemas/v1/report.json), `make check-report-schema` |

## Evidence links

| Artifact | Location |
|----------|----------|
| Workspace SBOM (CycloneDX + SPDX) | [sbom/v1/verilyze.cdx.json](sbom/v1/verilyze.cdx.json), [sbom/v1/verilyze.spdx.json](sbom/v1/verilyze.spdx.json) |
| Third-party license text | [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) |
| Dogfood scan reports | GitHub Actions artifact `dogfood-reports` from [supply-chain.yml](.github/workflows/supply-chain.yml) |
| Threat model | [architecture/PRD.md](architecture/PRD.md) section 11, [SECURITY.md](SECURITY.md) |
| Sample CI consumer | [examples/github-action-vlz-scan.yml](examples/github-action-vlz-scan.yml) |

## SBOM vs license attribution

- **`THIRD-PARTY-LICENSES`** -- human-readable license text from `cargo-about`
  (`make generate-third-party-licenses`).
- **`sbom/v1/*`** -- structured component inventory from `vlz scan`
  (`make generate-sbom`). Dogfoods CycloneDX/SPDX reporters (SEC-019).

## Reviewer sign-off (SEC-010)

| Field | Value |
|-------|-------|
| Reviewer | _Pending_ |
| Date | _Pending_ |
| Version / commit | _Pending_ |
| Notes | _Pending human security review_ |

## Gaps and roadmap

| Item | Status |
|------|--------|
| SLSA provenance for container image | Partial -- hand-written Cosign predicate; migrate to container generator |
| Reproducible release binaries (NFR-006) | Not validated in CI |
| Formal SOC 2 / ISO 27001 / CMMC certification | Out of scope for open-source project; matrix is self-assessment |
| Committed false-positive DB for CI CVE exceptions | Future -- use `vlz fp mark` workflow when needed |

Cross-references: [SECURITY.md](SECURITY.md), [architecture/PRD.md](architecture/PRD.md)
(sections 6--8, 10--11).
