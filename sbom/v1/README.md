<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Workspace SBOM (SEC-019)

This directory holds **machine-generated** Software Bill of Materials files for
the verilyze workspace, produced by dogfooding `vlz scan`:

- `verilyze.cdx.json` -- CycloneDX 1.6 JSON
- `verilyze.spdx.json` -- SPDX 3.0 JSON

Regenerate after dependency changes:

```sh
make generate-sbom
```

CI enforces freshness via `make check-sbom`.

**Relationship to `THIRD-PARTY-LICENSES`:** `THIRD-PARTY-LICENSES` (from
`cargo-about`) is human-readable license attribution text. Files here are
structured component inventories from resolved manifests and lockfiles.
