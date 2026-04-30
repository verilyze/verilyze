<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# OBS packaging workflow

This directory contains canonical packaging metadata for builds on
build.opensuse.org (OBS).

## Coordinates and namespace migration

OBS project/package coordinates are defined in one place:
`packaging/obs/obs-project.env`.

- `OBS_PROJECT` defaults to `home:tpost:verilyze`
- `OBS_PACKAGE` defaults to `verilyze`

To migrate from a personal namespace to a project-maintained namespace, update
`obs-project.env` first, then update OBS-side metadata as needed.

## Layout

- `packaging/obs/rpm`
  - `_service` for source ingestion
  - `_meta` for OBS package metadata
  - `verilyze.spec` for RPM targets (Fedora, RHEL, Rocky, openSUSE, SLE)
- `packaging/obs/debian`
  - `_service` for source ingestion
  - `_meta` for OBS package metadata
  - `debian/` canonical Debian packaging metadata for Debian and Ubuntu

## Source services

OBS source services use `tar_scm`, `recompress`, and `set_version` in manual
mode. Release automation triggers service refresh for tag-based releases.

## GitHub release automation

On every `v*` tag:

1. GitHub release artifacts are built and published.
2. `.github/workflows/release.yml` runs `scripts/obs-trigger-build.sh`.
3. The script reads `obs-project.env` and calls OBS API `runservice` then
   `rebuild`.

Required secret:

- `OBS_TOKEN` - least-privilege token with access to trigger service/build for
  the configured OBS project/package.

## Signing policy and verification

OBS repositories on `build.opensuse.org` are signed with an OBS project key.
For `verilyze`, this means the trust anchor is the key published for the
configured `OBS_PROJECT` in `packaging/obs/obs-project.env`.

Signing key sources:

- OBS web page:
  `https://build.opensuse.org/projects/<OBS_PROJECT>/signing_keys`
- OBS CLI:
  `osc signkey <OBS_PROJECT>`

Before trusting packages, verify that the published key fingerprint matches the
expected project key fingerprint you have recorded out-of-band for your release
process.

Suggested user verification:

- RPM ecosystems:
  - Import project key from OBS (`osc signkey <OBS_PROJECT> | rpm --import -`)
  - Verify package signature (`rpm --checksig <package.rpm>`)
- Debian/Ubuntu ecosystems:
  - Add the OBS project key to an apt keyring and use `signed-by=...` in the
    source list entry.
  - Verify repository metadata signatures during `apt update`.

Key rotation and expiration:

- Extend key lifetime with:
  `osc signkey --extend <OBS_PROJECT>`
- After extending or rotating keys, trigger OBS publish/rebuild so updated key
  metadata is visible in published repos.
- Run `make check-obs-packaging` to validate that OBS signing key metadata is
  present and structurally valid for the configured project.

## Versioning

The root workspace version in `Cargo.toml` remains the source of truth. Release
tags follow `vX.Y.Z`. OBS trigger automation receives `X.Y.Z` from the release
workflow and logs it for traceability.

## cargo-deb convenience path

`cargo-deb` remains available for local convenience artifacts (`make deb`), but
canonical distro Debian metadata for OBS is under
`packaging/obs/debian/debian`.

`make check-obs-packaging` validates:

- OBS coordinates are present in `obs-project.env`
- Debian package name remains `verilyze`
- `cargo-deb` metadata block remains present in `crates/core/vlz/Cargo.toml`
- OBS signing key metadata is published for the configured project
