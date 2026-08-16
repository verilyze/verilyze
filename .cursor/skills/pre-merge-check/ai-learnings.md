<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# AI learnings

Preserve failure evidence from CI and from local gates when the failure is
systemic. Feed confirmed gaps into deduplicated GitHub issues labeled
**`ai-learnings`** with Issue Type **`Learning`**, then promote each into
the cheapest durable gate.

This file is the **in-repo source of truth**. Personal skills must follow it;
do not maintain a second policy copy.

Learning is **independent of discovery venue and Git topology**: routine
change defects are fixed in place; systemic gaps become issues. PR comments
apply only when a PR already exists (typically CI).

---

## Context budget

- Do **not** paste open `ai-learnings` bodies into always-on rules or a growing
  learnings dump.
- Search **on demand** when CI fails, a local gate fails for a suspected
  systemic reason, or the task matches a known gap.
- Cap search at `--limit 5`; fingerprint / gate first.
- Prefer executable gates over long prose. Keep promotions short; prune
  superseded bullets when closing an issue.

### Human filters (opt-out / opt-in)

GitHub cannot force a default Issues filter for every visitor. Use saved
searches or the Types dropdown:

| View | Search |
|------|--------|
| Default product backlog | `is:issue is:open -label:ai-learnings` (or `-type:Learning`) |
| Opt-in learnings queue | `is:issue is:open label:ai-learnings` (or `type:Learning`) |

Agents keep searching `label:ai-learnings` (primary). Optional secondary:
`type:Learning`. Do not invent other type names; the org type is **`Learning`**.

---

## Classification

| Classification | Meaning | Create issue? |
|----------------|---------|---------------|
| `change defect` | Bug or mistake in this PR's changes | No (one-off) |
| `flaky/infrastructure` | Transient infra or unrelated flake | No (note in comment) |
| `base-branch failure` | Failure on base, not PR head | No (stop queue) |
| `missing local parity` | Local gate missing or weaker than CI | Yes (systemic) |
| `local gate not invoked` | Required local target was skipped | Yes (systemic) |
| `uncertain` | Not yet sure; still need a durable fingerprint | Yes (recurrence 1) |

**Why `uncertain` still gets an issue:** PR comments are not a reliable
cross-session index. Another agent on a later PR will not find "first
sighting" fingerprints unless they live on a labeled issue. Create the issue
at recurrence **1** with classification `uncertain`; bump recurrence and
reclassify when evidence strengthens.

**Primary signal:** classification. **Secondary:** recurrence counter.

- Higher recurrence prioritizes which open issues to promote first
- Reclassify `uncertain` to a systemic class when confirmed; then promote

---

## Title prefixes (label `ai-learnings`, type `Learning`)

- `ci-gap: <gate> -- <short description>` -- CI / local parity
- `agent: <area> -- <short description>` -- process / workflow mistakes

Every create via the wrapper sets Issue Type **`Learning`** and label
**`ai-learnings`**. One issue per distinct **fingerprint**
(`<gate-or-area>:<stable-prefix>`). Reuse (comment + bump recurrence) when
the fingerprint matches; do not open a mega-issue or a duplicate.

---

## Safe posting (secrets) -- mandatory

**Do not** call raw `gh issue create`, `gh issue comment`, or `gh pr comment`
for AI learnings failure evidence (CI or local). Use the wrappers so gitleaks
always runs and temp bodies are cleaned up:

| Goal | Command |
|------|---------|
| Create issue | `./scripts/ai-learnings-gh-post.sh issue-create --title '...' --body-file F` |
| Comment on issue | `./scripts/ai-learnings-gh-post.sh issue-comment <n> --body-file F` |
| PR failure record | `./scripts/ai-learnings-gh-post.sh pr-comment <n> --body-file F` |
| Body on stdin | add `--stdin` instead of `--body-file` (temp file removed on EXIT) |
| Preflight only | `./scripts/ai-learnings-gitleaks-preflight.sh <body-file>` |

1. Prefer **links** (Actions run URL, job URL, PR URL, SHA) over log bodies.
   Do not attach full workflow logs or downloaded artifacts.
2. Allowlist evidence only: fingerprint, gate/check name, classification,
   one-line assertion or error type, sanitized ci-investigator summary, local
   repro **command name** (not env dumps). Max ~40 lines if any excerpt is
   needed.
3. If `gh` lacks write access: leave a **link-only** note for a human; do not
   paste logs.
4. Repo secret scanning is a backstop after the fact; the wrappers are the
   preventive control.

Caller-owned body files: pass `--rm-body` to delete after a successful post,
or `rm -f` yourself. Never leave excerpts with possible secrets in `/tmp`.

---

## Local failure path

When a **local** gate fails during pre-merge validation, ship-pr, or an
explicit merge-readiness check:

1. **Classify** (table above). Default is fix-and-re-run; do **not** open an
   issue by default.
2. Default for "the gate correctly caught a defect in this branch":
   `change defect` -- fix and re-run only; **no** issue and **no** PR
   comment.
3. Invoke issue create/bump only after a **clear systemic signal** (see
   signals below), not because a gate merely failed. Classes that may file:
   `missing local parity`, `local gate not invoked`, or `uncertain` with a
   durable fingerprint. Then fingerprint-search (section 2) and create or
   bump via `scripts/ai-learnings-gh-post.sh` only.
4. **PR comments:** Use the section 1 **CI failure record** template only for
   GitHub Actions failures. For local-only findings (whether or not a PR
   already exists), do **not** post that template; use issues for systemic /
   `uncertain` intake. If a PR exists and classification is
   `flaky/infrastructure`, a short note comment is optional; still no CI
   failure record.
5. Do **not** run **ci-investigator** for local-only failures (CI jobs only).
6. Do **not** auto-post on every failed make in a reactive companion-sync
   loop ("out of sync; run `make generate-...`") unless the same process miss
   recurs across sessions with a stable fingerprint (`agent:` title).

Signals that raise suspicion of systemic (still require judgment; not
automatic create):

- A required [targets.md](targets.md) row was never run before the failure
  surfaced under a broader target
- Failure appears only under a gate that ship-pr / `check-fast` does not
  hard-require, but CI does
- The same fingerprint recurs across ship or pre-merge sessions with
  different PR contents

Allowlisted local evidence: fingerprint, gate/check name, classification,
one-line assertion or error type, local repro **command name** (not env
dumps or full logs). Prefer links (PR URL, SHA) when available. For
local-only issues, omit Actions run/job URLs rather than inventing them.

---

## 1. Post evidence before changing the branch tip

On each failed CI attempt, write a structured PR comment **before** any amend,
rebase, or force push, via `ai-learnings-gh-post.sh pr-comment`:

```markdown
## CI failure record

**Attempt:** <n>/3
**Failed SHA:** `<full-sha>`
**Branch:** `<branch>`
**Classification:** <see Classification>

### Failed checks

| Check | Run URL | Job |
|-------|---------|-----|
| check | https://github.com/.../actions/runs/<id> | check |

### Error fingerprint

`<gate>:<stable-error-prefix>`

### Evidence

(links preferred; allowlisted fields only; max ~40 lines)

### ci-investigator summary

<one sanitized paragraph>

### Local reproduction

- **Reproduces locally:** yes / no / not tried
- **Command run:** `make ...`
- **Result:** pass / fail / N/A

### Scoped fix

<one-line description of planned or applied fix>
```

Super-linter: download `super-linter-logs` via `gh run download` for local
diagnosis only; do not paste artifact contents into issues or PR comments.

---

## 2. Search before create

```bash
gh issue list --search "label:ai-learnings <fingerprint>" --state all --limit 5
gh issue list --search "label:ai-learnings <gate>" --state open --limit 5
```

| Situation | Action |
|-----------|--------|
| Match exists | Comment + **bump recurrence** (below) |
| No match; systemic or `uncertain` | Create new issue (recurrence 1) via wrapper |
| Duplicate issues found | Close newer as duplicate; point at canonical |

### Bump recurrence (concrete)

When the same fingerprint matches open issue `<n>`:

1. Read the current body and note the Recurrence integer (default 1 if absent):

```bash
gh issue view <n> --json body,title -q .body
```

2. Set `NEW=$((OLD + 1))`.
3. Comment with new evidence and an explicit line `**Recurrence:** <NEW>`:

```bash
./scripts/ai-learnings-gh-post.sh issue-comment <n> --body-file F
```

4. Edit the issue body so the Recurrence field/section equals `<NEW>` (keep
   other sections). Write the updated body to a file, preflight via the
   comment/create wrappers or `ai-learnings-gitleaks-preflight.sh`, then:

```bash
./scripts/ai-learnings-gitleaks-preflight.sh updated-body.md
gh issue edit <n> --body-file updated-body.md
rm -f updated-body.md
```

Do not only comment without updating the body Recurrence value.

Issue form: [`.github/ISSUE_TEMPLATE/ai-learnings.yml`](../../../.github/ISSUE_TEMPLATE/ai-learnings.yml).

Example create:

```bash
./scripts/ai-learnings-gh-post.sh issue-create \
  --title "ci-gap: <gate> -- <short description>" \
  --body-file "${BODY}" \
  --rm-body
```

The wrapper always passes `--type Learning` and `--label ai-learnings`
(not overridable).

Do not mix systemic promotions into the PR being repaired unless already in
scope.

---

## 3. Promotion order (cheapest first)

1. Executable test or Make gate
2. [targets.md](targets.md) and matching
   [ci-validation.mdc](../../rules/ci-validation.mdc) (keep in sync)
3. [AGENTS.md](../../../AGENTS.md) / [CONTRIBUTING.md](../../../CONTRIBUTING.md)
4. Git hook
5. Cursor rule / skill / hook

When the layer lands: close the issue with the PR link; remove or shorten any
temporary AGENTS/skill note the gate now covers. If obsolete or false
systemic: close as not planned with a short note.

---

## 4. CI triage hook

When investigating a failed PR check **or a failed `release.yml` run**:

1. Run **ci-investigator** on the failed job
2. Fingerprint-search `ai-learnings` (open and closed, `--limit 5`) before
   inventing a fix
3. Post evidence and file/update issues only via
   `scripts/ai-learnings-gh-post.sh`

For local-only systemic findings, use the **Local failure path** above
instead of this section.
