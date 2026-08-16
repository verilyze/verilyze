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
(e.g. "cut the next release", "prepare and publish 0.2.3", "push release tag
v0.2.3", "draft a release PR only"). Do **not** bump versions, tag, or push
release tags without that prompt.

### One-time kickoff confirm (allowed)

It is OK to ask the user for approval **once**, at the **start** of the
process (target: within the first ~20 seconds of the agent turn). Bundle
everything that needs a human decision into that single message:

- Intent mode (**Prepare only** vs **Publish**)
- Proposed SemVer (if unspecified or ambiguous)
- That Publish includes PR merge, signed tag push, stabilization tag moves,
  and any follow-ons named in the request

After the user confirms (or when the original message already states clear
Publish intent **and** a clear version), do **not** ask again for chat
confirmation between later steps.

Skip the kickoff confirm when the ask already names both intent and version
unambiguously (e.g. "cut and publish v0.8.0", "draft release PR for 0.8.0
only -- do not tag").

### Intent modes

Classify the request once (via the kickoff confirm if needed), then run that
mode without re-asking for the same steps:

| Mode | Example phrases | Agent may |
|------|-----------------|-----------|
| **Prepare only** | "draft the release PR", "bump to X.Y.Z but don't publish", "prepare release PR only" | CHANGELOG, version bump, packaging, open PR; merge only if explicitly asked; **no** tag, tag push, or stabilization tag move |
| **Publish** | "cut a release", "prepare and publish", "full release", "push release tag vX.Y.Z", "cut then run nightly" | Full path through signed tag push, `release.yml` watch, and stabilization until success (or a hard stop below) |

Treat bare "prepare release" / "prepare a release" as **ambiguous**: include
intent in the kickoff confirm; do not assume Publish or Prepare only.

A confirmed **Publish** ask is a **one-shot grant** for: SemVer, release PR,
merge, signed tag, tag push, monitoring, draft cleanup, and tag moves during
stabilization. Do **not** stop for chat confirmation between those steps.

### Non-interactive Publish

Phrases such as **non-interactive**, **non-interactively**, or **without
asking** plus a clear Publish version skip the kickoff confirm and forbid
further chat questions. After required CI checks are green, merge with
admin bypass (sole-contributor ruleset: one required review that the
author cannot satisfy):

```sh
gh pr merge <n> --merge --admin
```

Do **not** enqueue the merge queue without `--admin`. That path stays
`REVIEW_REQUIRED` / `BLOCKED` until a second reviewer or a manual GitHub
merge.

Do **not** put `git tag`, `git push origin v*`,
`git push origin :refs/tags/`, or `gh release delete` in the Shell
command string. Use only:

```sh
make release-tag-push TAG=vX.Y.Z
make release-tag-move TAG=vX.Y.Z
```

(equivalent: `./scripts/release-signed-tag.sh push|move vX.Y.Z`).

Those commands are the allowlist shape. Cursor Auto-review still
classifies the command text; wrapping does not disable the classifier.
Add the `make release-tag-*` (or script) pattern to Cursor Auto-run /
command allowlist so Publish is not blocked by a native card. If a card
still appears, retry with `request_smart_mode_approval` (section below);
do not ask in chat.

If the same message names a follow-on after a successful release (e.g. run
`verilyze-nightly`), run it after `release.yml` succeeds without another
confirm.

### Version selection

If the target version is clear, use it. If unspecified, propose SemVer from
CONTRIBUTING.md in the kickoff confirm (or announce and proceed when Publish
intent and version are already unambiguous). Wait for the kickoff reply when
SemVer is genuinely ambiguous (e.g. conflicting major vs minor signals).

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
4. Under **Publish** (or Prepare only when merge was explicitly requested):
   wait for CI green; `gh pr merge --merge --admin`.
5. `git checkout main && git pull origin main` locally.
6. Under **Publish** only: tag the merged commit on `main`; push **only** the
   tag (workflow steps 11-12).

Pushing `vX.Y.Z` triggers `release.yml`; pushing `main` is not required for
publish and bypasses project review policy.

## Workflow

0. **Kickoff** -- If intent or version is missing/ambiguous, send the one-time
   kickoff confirm immediately; wait for the reply before editing files.
1. **CHANGELOG** -- Add curated `## [X.Y.Z]` to CHANGELOG.md; draft bullets
   from `git log` since last tag; human may edit before commit. Add version
   bullets only; do not edit the CHANGELOG header or add maintainer workflow
   text there (see CONTRIBUTING release checklist step 1).
2. **Version bump** -- `[workspace.package].version` in root `Cargo.toml` only
3. **`make generate-packaging`**
4. **`make release-preflight`** (CHANGELOG, OBS/packaging, upload round-trip)
5. **Full gate** -- `make -j check` (use shell subagent in background if helpful)
6. **Branch and commit** -- create `release/vX.Y.Z` from `main`; signed commit
   (`chore: prepare vX.Y.Z release`)
7. **Pull request** -- `git push -u origin release/vX.Y.Z`; `gh pr create`
8. **Prepare only stop** -- If mode is **Prepare only**, stop here (open PR)
   unless the user explicitly asked to merge without publishing. Do not run
   steps 9-14. Do not create or push a `v*` tag.
9. **Merge** (**Publish**, or Prepare only when merge was requested) -- wait
   for CI green; merge with `gh pr merge <n> --merge --admin` (do not push
   `main` directly; do not use merge-queue-only merge on Publish)
10. **Sync local `main`** -- `git checkout main && git pull origin main`
11. **Pre-tag gate (required)** -- on merged `main`, `make release-preflight`
    must pass before tagging. Re-run if the release PR touched `release.yml` or
    `scripts/release-*.sh`. Optional alone: `make release-verify-upload`.
12. **Tag + push** (**Publish** only) -- after merge + preflight, create and
    push the signed tag in one step (no second chat confirm):
    `make release-tag-push TAG=vX.Y.Z`
    (never bundle with `git push origin main`; never inline `git tag` /
    `git push origin v*` in the agent Shell command)
13. **Monitor** -- `gh run watch --workflow=release.yml`; then
    `gh release view vX.Y.Z`. On **failure**, run **AI learnings intake**
    (below) **before** editing the fix branch tip or moving the tag.
14. **Follow-ons** -- if the original request named post-success work (e.g.
    `verilyze-nightly`), run it after `release.yml` succeeds
15. **Preview notes anytime** -- `make release-notes VERSION=x.y.z`

## Cursor auto-review (tag push / tag move)

Tag push and remote tag delete/repush often trigger Cursor Auto-review
when the Shell command contains `git tag`, `git push origin v*`, or
`gh release delete`. That card is a product safety prompt, not a GitHub
review and not a chat question.

**Required invocation:** only `make release-tag-push TAG=vX.Y.Z` or
`make release-tag-move TAG=vX.Y.Z` (or `./scripts/release-signed-tag.sh`
with the same mode). The script performs signed tag create, tag-only
push, draft GitHub Release delete, and remote tag delete.

**Allowlist (human, once):** in Cursor Settings, add Auto-run / command
allowlist entries that match those exact commands, for example:

- `make release-tag-push*`
- `make release-tag-move*`
- `./scripts/release-signed-tag.sh*`

Allowlist is the way to skip the native card. The repo cannot turn
Auto-review off. A stable command string is necessary so the allowlist
matches every release.

Under **Publish**, a stabilization loop, or an explicit **non-interactive**
ask, if Auto-review still blocks:

1. Attempt the make/script command normally first.
2. If blocked, **immediately retry the exact same command** with
   `request_smart_mode_approval: true` and the exact
   `smart_mode_block_reason` from the rejection. Do **not** ask in chat.
3. If the user dismisses or skips the card, tell them to Approve it, add
   the allowlist pattern, or run `make release-tag-push TAG=...` /
   `make release-tag-move TAG=...` themselves; continue when they do.

These cards do not replace the kickoff confirm and do not count as a
second chat prompt.

## Optional deeper checks

- OBS packaging changed: `make obs-upload-dry-run`
- After Renovate super-linter digest bump: `make super-linter-full` (Docker)

## Failure recovery

Before deleting a GitHub Release, confirm it is still a draft:

```sh
gh release view vX.Y.Z --json isDraft,url
```

If `isDraft` is true and publish failed:

```sh
gh release delete vX.Y.Z --yes
```

If it is not a draft, do **not** delete or move the tag; stop and cut
`X.Y.(Z+1)` instead.

Under **Publish**, fix the root cause and continue the stabilization loop
without waiting for another chat confirm. Under **Prepare only**, do not
re-tag or push tags.

### AI learnings intake (required on `release.yml` failure)

Do **not** skip this because the stabilization loop is in progress.

On each failed `release.yml` run (and on each later failed retry):

1. Fingerprint-search `label:ai-learnings` (`--limit 5`) per
   [ai-learnings.md](../pre-merge-check/ai-learnings.md).
2. Post evidence **only** via `scripts/ai-learnings-gh-post.sh` (gitleaks
   preflight). Prefer Actions run/job URLs over log bodies.
3. Create or bump one issue per fingerprint (`ci-gap: release.yml -- ...`
   or `agent: release-prepare -- ...`), type `Learning`, label
   `ai-learnings`. Recurrence 1 is required even when the class is
   `uncertain`.
4. Then continue the fix PR / tag-move loop. Do not treat "we will fix it
   in this session" as a reason to skip the issue.

Local `make` races (quota, `TMPDIR` inside the tree, venv rebuild) stay
`change defect` / infrastructure: no issue unless a durable fingerprint
recurs across sessions.

**Symptom guide** (v0.4.0 and v0.9.0 stabilization lessons):

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| SLSA job startup failure | Missing `contents: write` on provenance job | `release.yml` `binary-slsa-provenance` permissions |
| Empty macOS SLSA hash | Non-portable `base64` in `build-binary` | `base64 < checksum` in hash step |
| `create-release` cosign/SLSA verify fail | Generator SHA not in builder regex | `SLSA_GENERATOR_PIN_SHA` in `SLSA_GENERATOR_BUILDER_REGEX` |
| Draft re-verify: missing archives | Staging omitted archives or version mismatch | `release-stage-github-upload.sh`; `make release-verify-upload` |
| Draft has deb/rpm only, no archives | `path#name` in `action-gh-release` `files:` or empty `github-upload/` | Contract tests; stage flat archives under `github-upload/` |
| Draft `cli-contract-draft`: `release not found` | `GITHUB_TOKEN` `contents: read` cannot see drafts | Job needs `contents: write` |
| macOS draft install: `sha256sum` usage | BSD `sha256sum` has no GNU `-c` | `verify_sha256sums_entry` in `ci-install-vlz-release-common.sh` |
| Windows Cosign: SAN regex has `/.` | Git bash MSYS rewrites `\.` in env to `/.` | Identity regexes use `[.]` not `\.` |
| `publish-release`: `not a git repository` | Job has no checkout; `gh` infers repo from git | `gh release edit --repo "${GITHUB_REPOSITORY}"` |

## Release stabilization (before first successful publish)

Use **one** SemVer bump and **one** tag name until `release.yml` completes with
workflow conclusion `success`. Do **not** increment the patch version for each
CI or script fix during stabilization.

**When to use:** The release workflow failed due to fixable CI/script/secret
issues; `Cargo.toml` and `CHANGELOG.md ## [X.Y.Z]` are already correct for the
intended release. Under **Publish**, enter this loop automatically -- do not
wait for the user to say "move the tag".

**Loop** (at most **3** tag-move retries after the initial tag push; then stop
and report):

1. Fix on a branch with ordinary fix commits (no version bump); open PR; wait
   for CI green; merge to `main`. File or bump `ai-learnings` issues for
   the failed `release.yml` fingerprints first (intake above).
2. Add bullets under the existing `## [X.Y.Z]` section (not a new version
   header).
3. Sync `main`, re-run `make release-preflight`, verify the GitHub Release is
   still a draft (or absent), then move the tag locally and on origin
   (authorized by the original Publish grant):

```sh
make release-tag-move TAG=vX.Y.Z
```

4. Watch `gh run watch --workflow=release.yml` until success; if it fails again
   and a tag move is still allowed, repeat from step 1 until success or the
   retry cap.

**Agent-autonomous (do not ask):**

| Situation | Action |
|-----------|--------|
| Transient failure (network, rate limit, secret fixed in GitHub UI) | Re-run failed jobs on same tag/commit |
| Fixable CI/script failure; release still draft or absent | Learnings intake, then stabilization loop (tag move), within retry cap |

**Hard stops (ask the human):**

| Situation | Action |
|-----------|--------|
| Release already published (`isDraft=false` / publish succeeded) | Never move tag; cut `X.Y.(Z+1)` |
| `release-signed-tag.sh` cannot classify the GitHub Release (auth, network, unexpected `gh` error) | Stop; do not assume the release is absent |
| Immutable release or registry artifacts consumed downstream | New patch version only |
| Unrecoverable failure or missing secrets the agent cannot fix | Stop and report |
| Stabilization retry cap exceeded | Stop and report |

**Optional:** Run `workflow_dispatch` on `release.yml` from a branch ref to
exercise build and OBS jobs without pushing a tag. It does **not** run
`create-release` (tag push only). Use `make release-verify-upload` or
`make release-preflight` to rehearse publish layout before tagging. Tag push
remains the canonical publish for SemVer artifacts and GitHub Releases.

## Agent boundaries

| Intent / rule | Allowed |
|---------------|---------|
| **Kickoff confirm** | Once at start if intent/version unclear; bundle all decisions; then no mid-path chat reconfirms |
| **Prepare only** | Draft CHANGELOG, bump version, packaging, release branch, PR; merge if asked; **no** `v*` tag create/push/move |
| **Publish** | Everything in Prepare only, plus merge (`gh pr merge --admin` after CI), signed tag, tag push, draft release delete, stabilization tag moves (retry cap), and named follow-ons after success |
| `git push origin main` | **Never** (use PR merge per CONTRIBUTING) |
| Bump SemVer for each CI fix during stabilization | **Never** (same `X.Y.Z` until first successful publish) |
| Move tag after non-draft publish / immutable artifacts | **Never** (cut `X.Y.(Z+1)` instead) |

Never push a `v*` tag or publish a GitHub release without **Publish** (or an
explicit tag/publish ask) in the current conversation. Never push directly to
`origin/main`. Never put `git tag`, `git push origin v*`,
`git push origin :refs/tags/`, or `gh release delete` in the agent Shell
command; use `make release-tag-push` / `make release-tag-move` only.
