<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Dry-run verification scenarios

Walk through these scenarios mentally or on a test branch before relying on
the skill in production. Confirm each step matches the reference files.

---

## Scenario A: Dirty mixed work split into two PRs

**Setup:** Uncommitted changes in `scripts/foo.py` and `crates/bar/src/lib.rs`.

**Expected flow:**

1. Inventory shows two independent slices; present plan; user approves
2. Backup ref created; `queue.json` written with two slices
3. Slice 1 materialized on `main`; only `scripts/foo.py` staged
4. Full single-pr pipeline; PR opened with managed marker
5. CI green; merge; `main` synced
6. Slice 2 rematerialized on updated `main`; only Rust paths
7. Second PR shipped and merged; queue complete

**Verify:** Slice 2 branch never pushed before slice 1 `MERGED`.

---

## Scenario B: First PR CI failure, signed correction, merge

**Setup:** PR open; `check` fails on coverage.

**Expected flow:**

1. ci-investigator launched
2. Structured failure comment posted (SHA, run URL, excerpt, classification)
3. Fix applied; new signed conventional commit (not `fixup!`)
4. Local gates + super-linter; push
5. CI green on branch tip; merge with merge commit
6. No post-green history rewrite

**Verify:** PR has failure record comment + correction commit; `main` first-parent
shows one merge per PR.

---

## Scenario C: Behind-main rebase before next slice

**Setup:** Slice 1 merged; slice 2 branch was prepared earlier; `main` moved.

**Expected flow:**

1. `git checkout main && git pull --prune`
2. Rematerialize or rebase slice 2 onto `origin/main`
3. `${SHIP_PR_SH} force-push` (not `git merge origin/main`; do not inline `git push`)
4. Re-run path matrix, coverage, check-fast, super-linter

**Verify:** No merge commit from `origin/main` into feature branch.

---

## Scenario D: Resume from queue state

**Setup:** `queue.json` exists; slice 0 `merged`; slice 1 `pr_open`.

**Expected flow:**

1. Read manifest; resume at slice 1
2. Monitor CI or continue fix loop
3. Do not restart slice 0

**Verify:** `backup_ref` still present; no duplicate PR for slice 0.

---

## Scenario E: Opt-in single-commit amend path

**Setup:** User requested one commit per PR; CI fails once.

**Expected flow:**

1. Failure evidence posted before amend
2. Fix applied; `git commit --amend -s` (signed)
3. `${SHIP_PR_SH} force-push origin/<branch>:<sha>` with explicit lease
4. CI green on amended SHA; merge

**Verify:** Branch has one commit at merge time; no multi-commit-then-squash.

---

## Scenario F: Exceptional history cleanup

**Setup:** Accidental unrelated file committed; user approves cleanup.

**Expected flow:**

1. Backup ref created
2. Clean branch from `origin/main`; cumulative diff applied
3. All local gates pass; push with lease
4. Green CI on new tip; merge

**Verify:** Only runs with explicit approval; backup ref documented.

---

## Scenario G: Blocked / unrelated CI

**Setup:** PR head green locally but base-branch regression fails unrelated check.

**Expected flow:**

1. Classify as `base-branch failure`
2. Comment with evidence; stop queue
3. No broad CI weakening or unrelated fixes

**Verify:** Queue status `failed`; user notified with escalation template.

---

## Scenario H: Local parity miss caught before push

**Setup:** Path matrix / `check-fast` green; optional `make -j check` (or a
CI-required gate ship-pr omitted) fails locally before first push. No PR yet.

**Expected flow:**

1. Classify (e.g. `missing local parity` or `local gate not invoked`)
2. Fingerprint-search `label:ai-learnings` (`--limit 5`)
3. Create or bump issue via `ai-learnings-gh-post.sh` (no CI failure-record
   PR comment; omit Actions run URLs)
4. Fix matrix / run the missing gate; do not open a PR until local gates pass
5. No ci-investigator (local-only)

**Verify:** Issue exists with fingerprint; no CI failure-record PR comment;
push only after the stronger gate is green.

---

## Scenario I: Ship-managed vs CI triage automation

**Setup:** PR body contains `<!-- verilyze-ship-pr:managed -->`; active ship session.

**Expected flow:**

1. CI triage automation detects managed marker
2. Observes only; does not push fixes
3. Ship skill remains sole writer

**Verify:** No competing pushes from automation.
