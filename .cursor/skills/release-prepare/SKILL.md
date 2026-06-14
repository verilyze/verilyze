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

- On `main` (or the branch CONTRIBUTING specifies for releases), up to date
- Working tree clean or only intentional release files staged
- Commit signing configured (`git config commit.gpgsign`, tag signing enabled)
- `make -j check` green (or run it now)
- `make release-preflight` passes

## Workflow

1. **CHANGELOG** -- Add curated `## [X.Y.Z]` to CHANGELOG.md; draft bullets
   from `git log` since last tag; human may edit before commit
2. **Version bump** -- `[workspace.package].version` in root `Cargo.toml` only
3. **`make generate-packaging`**
4. **`make release-preflight`**
5. **Full gate** -- `make -j check` (use shell subagent in background if helpful)
6. **Commit** -- signed commit with conventional message when user asked to
   complete the release prep (e.g. `release: prepare vX.Y.Z`)
7. **Merge / push branch** -- if release prep is on a PR, ensure merged to
   `main` and CI green before tagging
8. **Tag** -- when user explicitly asks to tag or publish:
   `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
9. **Push tag** -- only after user confirms publish intent:
   `git push origin vX.Y.Z`
10. **Monitor** -- `gh run watch --workflow=release.yml`; then
    `gh release view vX.Y.Z`
11. **Preview notes anytime** -- `make release-notes VERSION=x.y.z`

## Optional deeper checks

- OBS packaging changed: `make obs-upload-dry-run`
- After Renovate super-linter digest bump: `make super-linter-full` (Docker)

## Failure recovery

If draft release exists but publish failed:

```sh
gh release delete vX.Y.Z --yes
```

Fix root cause; re-tag only after user confirms.

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
exercise build and OBS jobs without pushing a tag. Tag push remains the
canonical publish for SemVer artifacts and GitHub Releases.

## Agent boundaries

| Action | When |
|--------|------|
| Draft CHANGELOG / bump version | User asked to prepare release |
| Commit release prep | User asked to prepare or complete release |
| Create signed tag | User explicitly asked to tag or publish |
| Push tag to origin | User explicitly confirmed publish (separate confirm if ambiguous) |
| Delete draft release / force-push tag | User explicitly requested recovery |
| Move release tag (`git push origin :refs/tags/vX.Y.Z`) | User explicitly requested stabilization retry |

Never push a `v*` tag or publish a GitHub release without explicit user intent
in the current conversation.
