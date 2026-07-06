<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# JSON schemas

Versioned JSON Schema definitions for machine-readable `vlz` outputs (DOC-005).

| Path | Description |
|------|-------------|
| [v1/report.json](v1/report.json) | `vlz scan --format json` report contract (NFR-014) |

**Versioning:** Breaking changes to a schema require a new path (for example
`schemas/v2/report.json`). Non-breaking additions may stay on the current
version when consumers tolerate unknown fields (this schema uses
`additionalProperties: false` on objects, so additive fields require a bump).

Validate locally:

```sh
make check-report-schema
```
