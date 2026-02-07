# Compliance overview

This document is a placeholder for the compliance checklist required by
SEC-010 and DOC-008. It will map security and operational controls to
concrete implementation in the codebase (SOC 2, ISO 27001, CMMC baseline).

## Intended content (roadmap)

- **Data protection:** How cached CVE data and false-positive markings
  are stored, accessed, and protected (e.g. file permissions, SEC-014).
- **Auditability:** Error logging, exit codes, and audit trail (SEC-009,
  NFR-013).
- **Least privilege:** No privilege escalation, no set-UID (SEC-003,
  OP-001).
- **Secure communications:** TLS verification, certificate validation
  (SEC-002, NFR-004).

## Current location of controls

- Security requirements: [architecture/PRD.md](architecture/PRD.md)
  (sections 6--Security Requirements, 11--Risk & Threat Model).
- Operational and configuration requirements: PRD sections 7-8.
- Compliance checklist: this file (to be expanded and signed off by a
  security reviewer).
