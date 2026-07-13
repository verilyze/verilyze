---
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

name: release-prepare
description: Prepares or executes a verilyze release cut when the user explicitly requests it. Use only when the user asks to prepare a release, bump version, cut or push release vX.Y.Z, or run the release workflow. Do not start release work proactively.
---

# Release prepare

## Authorization (required)

Start this workflow **only** when the human explicitly asks for a release
(e.g. "prepare release 0.2.3", "cut the next release", "push release tag
v0.2.3"). Do **not** bump versions, tag, or push release tags without that
prompt.

If the target version is unclear, propose one from SemVer rules in
CONTRIBUTING.md and **wait for confirmation** before editing `Cargo.toml`.

## Prerequisites (check before tagging)

- Base branch `main` up to date with `origin/main` before starting release prep
- Working tree clean or only intentional release files staged
- Commit signing configured (`git config commit.gpgsign`, tag signing enabled)
- `make -j check` green (or run it now)
- `make release-preflight` passes (includes local publish layout round-trip via
  `scripts/release-verify-upload-roundtrip.sh`)

## Never push directly to `main`

`main` is branch-protected (PR reviews, CI, signed commits). Agents must
**not** run `git push origin main` when cutting a release.

Use a release branch and PR instead:

1. Branch from current `main` (e.g. `release/vX.Y.Z`).
2. Commit release prep on that branch.
3. `git push -u origin release/vX.Y.Z` and open a PR to `main`.
4. Wait for CI green; merge with `gh pr merge` (or human review).
5. `git checkout main && git pull origin main` locally.
6. Tag the merged commit on `main`; push **only** the tag (step 9 below).

Pushing `vX.Y.Z` triggers `release.yml`; pushing `main` is not required for
publish and bypasses project review policy.

## Workflow

1. **CHANGELOG** -- Add curated `## [X.Y.Z]` to CHANGELOG.md; draft bullets
   from `git log` since last tag; human may edit before commit
2. **Version bump** -- `[workspace.package].version` in root `Cargo.toml` only
3. **`make generate-packaging`**
4. **`make release-preflight`** (CHANGELOG, OBS/packaging, upload round-trip)
5. **Full gate** -- `make -j check` (use shell subagent in background if helpful)
6. **Branch and commit** -- create `release/vX.Y.Z` from `main`; signed commit
   when user asked to complete release prep (`chore: prepare vX.Y.Z release`)
7. **Pull request** -- `git push -u origin release/vX.Y.Z`; `gh pr create`;
   wait for CI green; merge to `main` (do not push `main` directly)
8. **Sync local `main`** -- `git checkout main && git pull origin main`
9. **Pre-tag gate (required)** -- on merged `main`, `make release-preflight`
   must pass before tagging. Re-run if the release PR touched `release.yml` or
   `scripts/release-*.sh`. Optional alone: `make release-verify-upload`.
10. **Tag** -- when user explicitly asks to tag or publish:
    `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
11. **Push tag** -- only after user confirms publish intent:
    `git push origin vX.Y.Z` (never bundle with `git push origin main`)
12. **Monitor** -- `gh run watch --workflow=release.yml`; then
    `gh release view vX.Y.Z`
13. **Preview notes anytime** -- `make release-notes VERSION=x.y.z`

## Optional deeper checks

- OBS packaging changed: `make obs-upload-dry-run`
- After Renovate super-linter digest bump: `make super-linter-full` (Docker)

## Failure recovery

If draft release exists but publish failed:

```sh
gh release delete vX.Y.Z --yes
```

Fix root cause; re-tag only after user confirms.

**Symptom guide** (v0.4.0 stabilization lessons):

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| SLSA job startup failure | Missing `contents: write` on provenance job | `release.yml` `binary-slsa-provenance` permissions |
| Empty macOS SLSA hash | Non-portable `base64` in `build-binary` | `base64 < checksum` in hash step |
| `create-release` cosign/SLSA verify fail | Generator SHA not in builder regex | `SLSA_GENERATOR_PIN_SHA` in `SLSA_GENERATOR_BUILDER_REGEX` |
| Draft re-verify: missing `vlz-*` paths | Duplicate `vlz` asset names or missing binaries on draft | Staging + restore scripts; `make release-verify-upload` |
| Draft has deb/rpm only, no binaries | `path#name` in `action-gh-release` `files:` | Contract tests; stage flat names under `github-upload/` |

## Release stabilization (before first successful publish)

Use **one** SemVer bump and **one** tag name until `release.yml` completes with
workflow conclusion `success`. Do **not** increment the patch version for each
CI or script fix during stabilization.

**When to use:** The release workflow failed due to fixable CI/script/secret
issues; `Cargo.toml` and `CHANGELOG.md ## [X.Y.Z]` are already correct for the
intended release.

**Loop:**

1. Fix on the release branch with ordinary fix commits (no version bump).
2. Add bullets under the existing `## [X.Y.Z]` section (not a new version header).
3. Move the tag locally and on origin (requires explicit user approval):

```sh
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
git tag -s vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

4. Watch `gh run watch --workflow=release.yml` until success.

**When not to move the tag:**

| Situation | Action |
|-----------|--------|
| Transient failure (network, secret fixed in GitHub UI) | Re-run failed jobs on same tag/commit |
| Release already published (`gh release edit --draft=false` succeeded) | Never move tag; cut `X.Y.(Z+1)` |
| Immutable release or registry artifacts consumed downstream | New patch version only |

**Optional:** Run `workflow_dispatch` on `release.yml` from a branch ref to
exercise build and OBS jobs without pushing a tag. It does **not** run
`create-release` (tag push only). Use `make release-verify-upload` or
`make release-preflight` to rehearse publish layout before tagging. Tag push
remains the canonical publish for SemVer artifacts and GitHub Releases.

## Agent boundaries

| Action | When |
|--------|------|
| Draft CHANGELOG / bump version | User asked to prepare release |
| Commit release prep on `release/vX.Y.Z` branch | User asked to prepare or complete release |
| Push release branch / open PR | User asked to prepare or complete release |
| Merge release PR | CI green; user asked to complete release |
| `git push origin main` | **Never** (use PR merge per CONTRIBUTING) |
| Create signed tag | User explicitly asked to tag or publish; after PR merged |
| Push tag to origin | User explicitly confirmed publish (separate confirm if ambiguous) |
| Delete draft release / force-push tag | User explicitly requested recovery |
| Move release tag (`git push origin :refs/tags/vX.Y.Z`) | User explicitly requested stabilization retry |

Never push a `v*` tag or publish a GitHub release without explicit user intent
in the current conversation. Never push directly to `origin/main`.
