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

- `packaging/obs/_service` -- canonical OBS source-service definition (RPM and
  Debian trees symlink here so there is a single file to maintain).
- `packaging/obs/rpm`
  - `_service` symlink to `../_service`
  - `_meta` for OBS package metadata
  - `verilyze.spec` for RPM targets (Fedora, RHEL, Rocky, openSUSE, SLE)
- `packaging/obs/debian`
  - `_service` symlink to `../_service`
  - `_meta` for OBS package metadata
  - `debian/` canonical Debian packaging metadata for Debian and Ubuntu

## Source services

OBS source services use `obs_scm`, `cargo_vendor`, `tar`, `recompress`, and
`set_version` in manual mode. Release automation triggers service refresh for
tag-based releases.

`cargo_vendor` runs after `obs_scm` against the unpacked source tree under
`verilyze/`. Current `obs-service-cargo` produces **only** `vendor.tar.zst`
(the Rust rewrite embeds `.cargo/config.toml`, `vendor/`, and a copy of
`Cargo.lock` inside that archive; older tooling used to emit `cargo_config` as
its own source file.)

The RPM spec and Debian `debian/rules` extract `vendor.tar.zst` atop the unpacked
upstream tree, then run `cargo build --release --locked --offline`.

**Troubleshooting:** After `osc service runall`, you should see `vendor.tar.zst`
in the package directory. If the `cargo_vendor` step prints nothing useful, run:

`osc service -vv run cargo_vendor`

Ensure the `obs-service-cargo` RPM is installed locally (often named
`obs-service-cargo` on openSUSE; `cargo_vendor` invokes that stack).

After running services locally (`osc service runall`) confirm `vendor.tar.zst`
is present before `osc commit`.

## GitHub release automation

On every `v*` tag:

1. GitHub release artifacts are built and published.
2. `.github/workflows/release.yml` runs `scripts/obs-trigger-build.sh`.
3. The script reads `obs-project.env` and POSTs to **`build.opensuse.org`**
   trigger endpoints only (not `api.opensuse.org`): `runservice` then `rebuild`.

Required repository secrets (OBS authorization tokens, scoped to the package):

- `OBS_TOKEN_RUNSERVICE` -- for `POST .../trigger/runservice`
- `OBS_TOKEN_REBUILD` -- for `POST .../trigger/rebuild`

Create them with `osc` (use the same project and package names as `obs-project.env`):

```bash
osc token --create <OBS_PROJECT> <OBS_PACKAGE>
osc token --operation rebuild --create <OBS_PROJECT> <OBS_PACKAGE>
```

Store each secret string in GitHub under the names above. GitHub Actions does
not upload `_service`; see **Maintainer release checklist** below.

## Maintainer release checklist

CI does not push `_service` to OBS. For a reproducible OBS build that matches a
**specific Git tag**, update the `_service` file **on the OBS package** before
or when cutting the release so `obs_scm` checks out that tag, for example:

```xml
<param name="revision">v0.2.1</param>
```

Release tags are `v` plus SemVer (`vX.Y.Z`); the GitHub workflow logs `X.Y.Z`
without the prefix.

After changing `_service` on OBS (web UI or `osc commit`), the release
workflow still runs `runservice` and `rebuild` so OBS refreshes sources and
builds.

Copy from `packaging/obs/_service` as a template when editing locally.

### `obs_scm` version after pinning `revision` to a tag

When `revision` points at an annotated tag, confirm the generated tarball
version matches what `verilyze.spec` and Debian metadata expect (for example run
the source services on OBS or `osc service run` in a checkout). Confirm that the
service output includes `verilyze-<version>.tar.xz`. Adjust `versionformat` or
packaging if the tag-based checkout differs from `main`.

Release tags use a leading `v` (`vX.Y.Z`). This tree sets `obs_scm`
**`versionrewrite-*`** so semver strings drop the leading `v` when possible (for
example `v0.2.1` becomes `0.2.1` in the archive basename).

The OBS **`set_version`** service uses a default tarball filename regex that
requires **a digit immediately after the last hyphen**. Names such as
**`verilyze-v0.2.1.obscpio`** therefore do **not** update **`Version:`** in the spec
unless **`set_version`** gets a custom **`regex`** (see `_service` here). Without that,
**`Version`** stays the placeholder (`0.1.0`), **`Source0`** expands to
**`verilyze-0.1.0.tar.xz`**, and **`%prep`** fails while **`Unpacking verilyze-v0.2.1.*`**
still shows the real SCM snapshot.

If OBS still resolves the wrong basename, inspect SOURCES on the worker:
**`osc ls -v home:tpost:verilyze verilyze`** and re-run services until
**`verilyze.spec`** **`Version`** and **`Source0`** match the staged archives.

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

## RPM dual-spec maintenance

This repository intentionally keeps two RPM spec files:

- `packaging/obs/rpm/verilyze.spec` is the source of truth for OBS builds.
- `packaging/rpm/SPECS/verilyze.spec` is the local `rpmbuild` variant.

The local spec is generated from the OBS spec with explicit divergence points
only for local packaging behavior (source format, version macro handling, and
offline vendor extraction differences).

Use:

- `make sync-rpm-specs` to regenerate `packaging/rpm/SPECS/verilyze.spec`
- `make check-rpm-spec-sync` to verify no drift in CI/local checks

Reassess this approach after 2-3 release cycles. If maintenance cost
remains high, evaluate moving to an explicit generator-first option workflow.

## cargo-deb convenience path

`cargo-deb` remains available for local convenience artifacts (`make deb`), but
canonical distro Debian metadata for OBS is under
`packaging/obs/debian/debian`.

`make check-obs-packaging` validates:

- OBS coordinates are present in `obs-project.env`
- Debian package name remains `verilyze`
- `cargo-deb` metadata block remains present in `crates/core/vlz/Cargo.toml`
- OBS signing key metadata is published for the configured project
