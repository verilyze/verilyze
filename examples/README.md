<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Examples

Sample integrations for verilyze (`vlz`).

| File | Description |
|------|-------------|
| [github-action-vlz-scan.yml](github-action-vlz-scan.yml) | GitHub Actions patterns: release binary, build from source, offline cache (NFR-014) |
| [gitlab-ci-vlz-scan.yml](gitlab-ci-vlz-scan.yml) | GitLab CI job: release binary, SARIF/JSON artifacts, FR-010 exit (NFR-014) |

See also:

- [INSTALL.md](../INSTALL.md) -- install and build
- [README.md](../README.md) -- CLI usage and exit codes
- [schemas/v1/report.json](../schemas/v1/report.json) -- JSON report schema (DOC-005)
- [docs/FAQ.md](../docs/FAQ.md) -- direct-only warnings and remediation
- Composite GitHub Action: `.github/actions/vlz-scan` (`uses: verilyze/verilyze/.github/actions/vlz-scan@<sha>`)
