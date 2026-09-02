<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Commit history policy

[CONTRIBUTING.md](../../../CONTRIBUTING.md) provides a clean mainline via merge commits
and `git log --first-parent`. Default ship behavior keeps signed correction
commits on the PR branch.

---

## Default (recommended)

Use unless the user explicitly requests single-commit mode.

- Keep focused, signed, DCO-compliant commits: test, implementation, and
  CI-repair commits stay separate.
- Use normal Conventional Commit messages for repairs. Do **not** use `fixup!`
  prefixes (commitlint may reject them).
- Rebase onto `origin/main` only when needed; push with
  `${SHIP_PR_SH} force-push`.
- Merge with `${SHIP_PR_SH} merge` once required checks pass on the
  branch tip.

**Why:** Preserves signatures, review history, CI-to-SHA associations, and
avoids an extra force push plus redundant CI on a reconstructed SHA.

### CI repair commits

After a CI failure:

1. Post evidence ([ci-learning.md](ci-learning.md))
2. Apply scoped fix locally
3. Re-run validation and super-linter
4. Create a **new signed commit** with a conventional message, e.g.
   `fix(ci): correct coverage for new script module`
5. Push normally (no force required unless rebasing)

---

## Opt-in single-commit mode

Activate only when the user explicitly requests one commit per PR **before**
the first push, or before the first push of a queue slice.

- Apply the repair, then **amend** the existing commit (or squash locally
  before initial push) so the branch still has one signed commit.
- Post failure evidence **before** any amend or force push.
- Push with `${SHIP_PR_SH} force-push` tied to the known remote SHA:

```bash
${SHIP_PR_SH} force-push origin/<branch>:<known-remote-sha>
```

- Do **not** obtain a green multi-commit tip and then rewrite it.

---

## Exceptional history cleanup

Reserve for genuinely unusable history: accidental unrelated commits, exposed
secrets, or similar.

**Requires:** explicit user approval + recoverable backup ref.

```bash
BACKUP=$(git rev-parse HEAD)
git update-ref "refs/backup/ship-cleanup-$(date +%s)" "$BACKUP"
```

Procedure:

1. Post evidence for any CI failures already observed
2. Create a clean branch from latest `origin/main`
3. Apply the cumulative diff as one or more new signed commits
4. Verify tree matches the intended green state
5. Re-run all local gates and super-linter
6. Push with lease; require green CI on the new tip before merge

Do not use this as the default ship path.

---

## Avoid

| Practice | Why |
|----------|-----|
| Mandatory post-green consolidation | Discards proven SHA; extra CI cycle |
| Amend-after-every-fix (default) | Disrupts review unless single-commit mode |
| `git merge origin/main` on feature branches | Conflicts with CONTRIBUTING rebase workflow |
| GitHub squash or rebase merge | Disabled; strips contributor signatures |
