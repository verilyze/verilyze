<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Changelog

Human-readable summaries for each release
([OpenSSF Best Practices `release_notes`](https://bestpractices.dev/en/criteria/0)).
The GitHub Release body is generated from the matching `## [version]` section
below when you push a `v*` tag (see `.github/workflows/release.yml`). Update
this file **before** creating the release tag.

## [Unreleased]

### Changed

- (Nothing yet -- move items here during development, then copy into the next numbered section before tagging.)

## [0.1.0] - 2026-04-09

First public GitHub-tagged release for the verilyze workspace at **0.1.0**
(see `Cargo.toml` `[workspace.package].version`).

### Added

- Core `vlz` CLI: scan, list, config, db, fp, generate-completions, help.
- SCA workflow: manifest discovery, dependency resolution, CVE lookup (OSV by default), reporting (plain, JSON, SARIF, HTML, CycloneDX, SPDX), cache and false-positive stores.
- Documentation: README, INSTALL, CONTRIBUTING, PRD, SECURITY, configuration reference, and man pages (when built with the `docs` feature).

### Notes for packagers and CI

- Release artifacts for this version are published via GitHub Release assets:
  Linux binary, `.deb`, `.rpm`, and GHCR container image tags.
- crates.io publishing and external distro/community repo publication are out of
  scope for this first release.
- `COMPLIANCE.md` remains an in-repo compliance roadmap placeholder for this
  release and will be expanded in subsequent releases.
- Merge-queue and release shell scripts validate Actions-fed inputs per PRD OP-019 (`scripts/lib/ci-input-validate.sh`).
