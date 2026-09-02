<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Split queue pipeline

Ship multiple independent slices **one PR at a time**. Each PR must merge and
sync `main` before the next is pushed.

Follow hard rules from the `split-to-prs` skill: plan approval before branches,
recoverable snapshots, stage only named files/hunks (no `git add -A`).

## Progress

See split-queue checklist in [reference.md](reference.md).

---

## 1. Inventory

Compare all work to `origin/main` (committed + uncommitted + unpushed):

```bash
git fetch origin main 2>/dev/null || true
git status
git diff origin/main...HEAD --stat
git diff --stat
git diff --cached --stat
```

Summarize independent slices by concern (use chat history for intent). Default
to independent PRs off `main`; stack only when dependency is real.

Present proposed slices (titles + file paths or hunks) and **wait for user
approval** before proceeding.

---

## 2. Snapshot and queue manifest

Before moving work, save a recoverable snapshot:

```bash
SHA=$(git stash create "pre-split-ship")
if [ -n "$SHA" ]; then
  git update-ref "refs/backup/ship-pre-split-$(date +%s)" "$SHA"
fi
```

Create queue directory and manifest (gitignored under `.git/`):

```bash
mkdir -p .git/verilyze-ship-pr
```

Write `.git/verilyze-ship-pr/queue.json`:

```json
{
  "version": 1,
  "repo": "verilyze/verilyze",
  "base_sha": "<origin/main at queue start>",
  "backup_ref": "refs/backup/ship-pre-split-<timestamp>",
  "created_at": "<ISO-8601>",
  "slices": [
    {
      "id": "slice-1",
      "title": "feat(scope): short subject",
      "branch": "feat/slice-one",
      "paths": ["path/a.rs", "scripts/b.py"],
      "status": "pending",
      "pr_number": null,
      "pr_url": null,
      "merged_at": null
    }
  ],
  "current_slice_index": 0,
  "lock_holder": "verilyze-ship-pr"
}
```

**Status values:** `pending`, `materialized`, `pushed`, `pr_open`, `ci_green`,
`merged`, `failed`, `skipped`.

Update the manifest after every stage transition.

---

## 3. Materialize current slice

For slice `N` (only when slice `N-1` is `merged` or `N == 0`):

1. `git checkout main && git pull --prune`
2. `git checkout -b <slice.branch>` from current `main`
3. Apply only this slice's paths/hunks from the backup ref or working tree:
   - `git checkout <backup_ref> -- <path>` for whole files, or
   - stage named hunks only
4. Set slice `status` to `materialized`

Never push slice `N+1` until slice `N` is `merged`.

---

## 4. Ship current slice

Run the full [single-pr.md](single-pr.md) pipeline for the materialized branch:

1. Local validation (path matrix, coverage, check-fast). On local gate
   failure: fix and re-run; for clear systemic signals follow
   [ci-learning.md](ci-learning.md) (**Local failure path**)
2. Signed commit(s) per [commit-policy.md](commit-policy.md)
3. `make super-linter`
4. `${SHIP_PR_SH} push` and `${SHIP_PR_SH} create-pr` (include `<!-- verilyze-ship-pr:managed -->` marker)
5. Monitor CI; on failure follow [ci-learning.md](ci-learning.md)
6. `${SHIP_PR_SH} merge` when green; confirm `MERGED`
7. `git checkout main && git pull --prune`
8. Set slice `status` to `merged`; increment `current_slice_index`

---

## 5. Next slice

If more slices remain:

1. Rebase or rematerialize the next slice onto updated `origin/main`
2. Re-run full local gates for that slice's diff
3. Repeat section 4

If a slice's paths conflict with merged work, rematerialize from backup rather
than merging `origin/main` into the old branch.

---

## 6. Resume interrupted queue

If a prior ship session stopped mid-queue:

```bash
cat .git/verilyze-ship-pr/queue.json
```

Resume from `current_slice_index` and the slice's `status`:

| Status | Action |
|--------|--------|
| `pending` | Materialize from step 3 |
| `materialized` | Continue validation from single-pr step 2 |
| `pushed` / `pr_open` | Monitor CI or fix loop |
| `ci_green` | Merge and advance |
| `failed` | Report; ask user whether to retry or abort queue |

Do not delete `backup_ref` or `queue.json` until all slices are `merged` or
the user requests cleanup.

---

## 7. Stop conditions

Stop the queue and report when:

- User rejects the split plan or a slice is ambiguous
- Unrelated CI failure on base branch (not PR scope)
- Permission or signing failure
- Max retry cycles exhausted on a slice
- Merge conflict intent clash

Preserve backup refs and queue manifest for recovery.

---

## 8. Cleanup (explicit user request only)

```bash
git update-ref -d refs/backup/ship-pre-split-<timestamp>   # only when asked
rm -rf .git/verilyze-ship-pr/
```
