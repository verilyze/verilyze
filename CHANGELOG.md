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

## [0.3.0] - 2026-07-03

### Added

- Python transitive dependency resolution when no lock file is found, with
  parallel resolution per manifest, batched error reporting, and new
  `fail_fast` and `allow_direct_only_fallback` options.
- Scan `setup.py` files via Ruff AST analysis for direct dependency CVE
  checks.
- Scan orphan lock files when no manifest is present; warn when multiple
  lock files exist in the same directory.
- `lock_file` allowlist configuration.

### Fixed

- OBS release upload always replaces and re-adds `vendor.tar.zst` so a prior
  delete on OBS cannot leave the package without vendored Rust sources.
- Post-upload checksum verification fails when OBS metadata omits an expected
  source file (catches delete-without-reupload commits).
- Disable OBS `Fedora_43` builds: worker Rust 1.90 cannot compile v0.3.0
  (Ruff-based setup.py support requires Rust 1.94+).
- Cursor agent validation no longer runs on read-only turns (plans, questions,
  reviews with no file edits).
- CI header and super-linter failures.
- Transient OBS build errors in release workflow.
- Removed unnecessary `rpmlintrc` from RPM packaging.

### Changed

- Dependency updates: GitHub Actions, `clap_complete`, Rust 1.96.1, and
  Docker base image digests.

## [0.2.4] - 2026-06-30

### Fixed

- Release workflow waits for OBS builds to succeed before publishing the
  GitHub Release.
- OBS upload verifies checksums on uploaded sources and removes stale
  source tarballs from the package directory.
- RPM packaging resolves rpmlint warnings in OBS builds.
- OBS project `_meta` drops Leap 15.7 target until `openSUSE:Leap:15.7`
  exists on build.opensuse.org (fixes release `publish-obs` sync).
- OBS upload verifies `.changes` checksum from the checkout render (not the
  seed-only dry-run digest).
- OBS upload stages untracked source archives with `osc add` and fails when
  `osc commit` reports no package changes.
- Release workflow skips OBS project `_meta` push when `--check` already
  matches live OBS (package upload does not require project PUT).
- OBS project `_meta` grants `verilyze-obs-bot` maintainer so release
  `publish-obs` can sync project metadata without HTTP 403.

### Changed

- OBS project and package `_meta` files in git are the single source of
  truth; the release workflow syncs them to build.opensuse.org.
- Dependency updates: Rust workspace crates, Python dev tooling, Docker
  base image digests, and click 8.4.2.

### CI

- Native codespell and super-linter checks run in `make check-fast`.
- Workflow permissions tightened for least-privilege (zizmor).

## [0.2.3] - 2026-06-13

### Fixed

- Release workflow gates GitHub Release promotion on successful OBS source
  upload, rebuild trigger, and completed OBS builds (`wait-obs-builds` job).
- OpenSSF Scorecard Packaging check: requires a fully successful release
  workflow run (including OBS jobs) so `docker push` to GHCR is recognized.
- OBS upload and build-wait scripts use shared `scripts/lib/osc-cmd.sh` with
  `--config` for the transient oscrc (not `-c`, which conflicts with `osc co`).
- OBS transient `oscrc` includes an apiurl-named section with credentials;
  Ubuntu apt `osc` ignores `OSC_*` env vars without it.

### Added

- `scripts/obs-wait-for-builds.sh` polls OBS build results for enabled build
  repositories derived from committed `_meta` files.
- `scripts/sync-obs-project-meta.sh` pushes `packaging/obs/project/_meta` to
  OBS on release (`--push`); supports `--pull` (bootstrap) and `--check`
  (drift detection).
- `scripts/obs_repositories.py` derives enabled repositories from project and
  package `_meta` files (replaces `OBS_WAIT_REPOSITORIES` in `obs-project.env`).
- `release.yml` supports `workflow_dispatch` to exercise build and OBS jobs
  from a branch ref without publishing a GitHub Release.

## [0.2.2] - 2026-06-07

### Fixed

- OBS upload-driven release flow replaces the broken `_service` pipeline on
  public `build.opensuse.org` (pre-generated tarball, vendor archive, and spec
  uploaded via `scripts/obs-upload-release-sources.sh`).
- RPM spec sync and OBS build reliability (`make sync-rpm-specs`,
  `make check-rpm-spec-sync`).
- Release workflow hardening:
  - draft GitHub Release before publish with local and downloaded asset
    verification.
  - sign all release artifacts including edge cases with missing artifacts.
  - OBS rebuild uses operation-scoped `OBS_TOKEN_REBUILD` tokens.

### Changed

- Dependency updates: Rust toolchain 1.96.0, workspace crates (redb, tokio,
  serde_json, and related), GitHub Actions pins, Docker base image digest,
  and REUSE tooling.

### Fixed (CI)

- Coverage nightly workflow Python venv caching.

## [0.2.1] - 2026-04-30

### Changed

- GitHub Release signing outputs now use Sigstore JSON bundles
  (`*.sigstore.json`) with `cosign verify-blob --bundle ...` instead of
  separate `.sig` and `.pem` files from older `cosign sign-blob` options.

### Fixed

- Release workflow regressions from `v0.2.0`:
  - `build-rpm` now installs `git` before `actions/checkout` in the Fedora
    container so `make rpm` can run `git archive` against a real `.git` tree.
  - container provenance attestation now includes the required SLSA `builder`
    field and avoids zizmor template-injection findings.

## [0.2.0] - 2026-04-30

### Added

- Initial reachability analysis (behind feature gates and configuration).
- OBS packaging metadata under `packaging/obs/` and release workflow trigger
  for `build.opensuse.org` (`scripts/obs-trigger-build.sh`).

### Changed

- Release workflow now fails early when the pushed tag does not match
  `[workspace.package].version` in `Cargo.toml` via
  `scripts/release-verify-tag-version.sh`.
- GitHub Release artifacts now include a `SHA256SUMS` manifest generated by
  `scripts/release-generate-checksums.sh`.
- Release artifact integrity metadata now includes keyless Sigstore signing for
  binary/package assets and `SHA256SUMS` (format details evolved in `v0.2.1`;
  see that section).
- GHCR release images are now keyless-signed and receive a provenance
  attestation during the release workflow.
- Performance improvements for reachability analysis.
- Dependency updates: rustls 0.23.40, redb 4.x, GitHub Actions minor/patch.

### Fixed

- Mermaid diagram output now includes reachability where applicable.

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
