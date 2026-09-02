---
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

name: verilyze-ship-pr
description: >-
  Commit, push, open, monitor, fix CI, admin-merge, and sync main for verilyze
  PRs. Optionally split unrelated work into a sequential PR queue. Use when the
  user asks to ship, commit and merge a PR, split and ship multiple PRs, or run
  the full PR pipeline after human review. verilyze-only; requires signed
  commits and gh admin merge bypass.
disable-model-invocation: true
---

# verilyze ship PR

End-to-end pipeline: local validation, signed commits, super-linter, push, open
or reuse PR, monitor CI, fix failures with preserved evidence, admin merge
(merge commit), sync `main`. Optionally split unrelated work and ship one PR
at a time until the queue is complete.

Run **only** when the user explicitly asks (e.g. "ship this PR", "split and
ship", "use verilyze-ship-pr"). **Human review is assumed complete** before
invocation.

## Do not

- Bump versions, tag releases, or start release work (see project
  `release-prepare` skill)
- Push directly to `origin/main`
- Update git config
- Use `--no-verify`, `--no-gpg-sign`, or skip hooks
- Modify root `LICENSE` or anything under `LICENSES/`
- Rewrite history (`reset --hard`, force-push, squash/reconstruct) without
  explicit user approval and recoverable backup refs (see
  [commit-policy.md](commit-policy.md))

## Project references (read at runtime in verilyze checkout)

- [AGENTS.md](../../../AGENTS.md) -- TDD, signing, conventions
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- commit messages, branching, companion files
- `.cursor/skills/pre-merge-check/SKILL.md` and `targets.md`
- `.cursor/rules/ci-validation.mdc`, `agent-workflow.mdc`, `testing.mdc`

On CI failure: launch **ci-investigator** on the failed job. Record evidence
per [ci-learning.md](ci-learning.md) (delegates to in-repo
`.cursor/skills/pre-merge-check/ai-learnings.md`). On local validation
failures that look systemic, follow the same in-repo **Local failure path**
(classify first; issues only for systemic / `uncertain`).

## Modes

| Mode | When | Procedure |
|------|------|-----------|
| **Single PR** | One focused branch or one slice of work | [single-pr.md](single-pr.md) |
| **Split queue** | Unrelated changes across paths or concerns | [split-queue.md](split-queue.md) |

If the user asks to split unrelated work, or inventory shows multiple
independent slices, use split queue. Otherwise use single PR.

## Workflow overview

**Single PR:**

```
preflight -> validate -> commit -> super-linter -> push -> PR
  -> watch CI -> [fix loop + evidence] -> merge -> sync main
```

**Split queue:**

```
inventory -> approve slices -> backup + queue manifest
  -> [per slice: materialize -> validate -> push -> PR -> CI -> merge -> sync]
  -> next slice only after prior PR MERGED
```

Track progress with checklists in [reference.md](reference.md).

## 0. Authorization

Confirm the user explicitly requested this pipeline. If the target repo is not
`verilyze/verilyze`, warn and stop unless the user confirms.

## 1. Choose mode

1. Compare all work (committed + uncommitted) to `origin/main`.
2. If multiple independent slices exist, follow [split-queue.md](split-queue.md)
   (plan approval required before branches/commits/PRs).
3. Otherwise follow [single-pr.md](single-pr.md).

## 2. Shared rules (both modes)

- **Ship-pr script:** Resolve once per session (cwd-independent inside the
  repo):

```bash
SHIP_PR_SH="$(git rev-parse --show-toplevel)/.cursor/skills/verilyze-ship-pr/scripts/ship-pr.sh"
```

  Invoke as `"${SHIP_PR_SH}" <mode>` (`push`, `force-push`, `merge`,
  `create-pr`). The script `cd`s to the repository root and refuses remote
  writes on `main`.

- **Signing:** `commit.gpgsign` must be `true`. Every pushed commit needs DCO
  (`-s`) and cryptographic signature.
- **Validation:** Read the verilyze **pre-merge-check** skill. Run path-scoped
  targets, scoped coverage, `make check-fast`, then `make super-linter` before
  every push. Details in [single-pr.md](single-pr.md) section 2 and
  [reference.md](reference.md). On local gate failure, default to fix-and-re-run;
  follow [ci-learning.md](ci-learning.md) / Local failure path only after a
  clear systemic signal (issues only; no CI failure-record PR comment).
- **CI failures:** Post structured evidence ([ci-learning.md](ci-learning.md)),
  fix in scope, push signed **correction commits** (default). Commit history
  policy: [commit-policy.md](commit-policy.md).
- **Behind main:** Rebase onto `origin/main`, then
  `${SHIP_PR_SH} force-push` (optional lease arg). Never
  `git merge origin/main` into a feature branch.
- **Remote writes:** Do **not** put `git push`, `git push --force-with-lease`,
  `gh pr create`, or `gh pr merge --admin` in the Shell command string. Use
  only `"${SHIP_PR_SH}"` with a mode (see Cursor Auto-review below).
- **Merge:** `${SHIP_PR_SH} merge` only when required checks pass on the
  branch tip. The script polls until `state == "MERGED"`.
- **Post-merge:** `git checkout main && git pull --prune` before the next slice.


## Cursor Auto-review / allowlist

Push, force-push, PR create, and admin merge often trigger Cursor Auto-review
when those strings appear directly in the Shell command. That card is a product
safety prompt, not a GitHub review and not a chat question.

**Required invocation:** only `"${SHIP_PR_SH}"` with mode
`push`, `force-push`, `merge`, or `create-pr`. Do not inline `git push`,
`git push --force-with-lease`, `gh pr create`, or `gh pr merge --admin`.

**Allowlist (human, once):** in Cursor Settings, add an Auto-run / command
allowlist entry that matches the script, for example:

- `*/verilyze-ship-pr/scripts/ship-pr.sh*`

Allowlist is the way to skip the native card. The skill cannot turn Auto-review
off. A stable command string is necessary so the allowlist matches every ship.

If Auto-review still blocks during an explicit ship request:

1. Attempt the `ship-pr.sh` command normally first.
2. If blocked, **immediately retry the exact same command** with
   `request_smart_mode_approval: true` and the exact
   `smart_mode_block_reason` from the rejection. Do **not** ask in chat.
3. If the user dismisses or skips the card, tell them to Approve it, add the
   allowlist pattern, or run `${SHIP_PR_SH} ...`
   themselves; continue when they do.

These cards do not count as an extra chat confirmation.

## 3. Ship-managed PR marker

When opening a PR from this skill, include in the body:

```html
<!-- verilyze-ship-pr:managed -->
```

The optional CI triage automation (personal, out-of-repo) observes but does
not modify ship-managed PRs while an active ship session holds the queue lock.

## 4. Retry and stop conditions

- Max **3** CI fix-and-push cycles per PR; then stop and report (template in
  [reference.md](reference.md)).
- Stop the queue on ambiguity, unrelated CI failure, permission failure, merge
  conflict intent clash, or retry exhaustion.
- Keep backup refs and queue state until the queue completes or the user
  requests cleanup.

## 5. What this skill cannot automate

- GPG/SSH signing setup (one-time machine config)
- GitHub admin / ruleset bypass permissions
- Flaky CI or failures requiring product decisions
- Mandatory post-green history rewrite (not default; see commit-policy.md)

## Reference files

| File | Contents |
|------|----------|
| [single-pr.md](single-pr.md) | Full single-PR pipeline steps |
| [split-queue.md](split-queue.md) | Split planning, queue manifest, sequential merge |
| [ci-learning.md](ci-learning.md) | Delegates to in-repo `ai-learnings.md` (CI + local) |
| [commit-policy.md](commit-policy.md) | Default, opt-in single-commit, exceptional cleanup |
| [reference.md](reference.md) | Checklists, commands, dry-run scenarios |
| [dry-run.md](dry-run.md) | Walkthrough verification scenarios |
