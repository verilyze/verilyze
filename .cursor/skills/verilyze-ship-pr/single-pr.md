<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Single-PR pipeline

Use for one focused branch or one approved queue slice.

## Progress

See single-PR checklist in [reference.md](reference.md).

---

## 1. Preflight

Run in parallel where possible:

```bash
git status
git diff
git diff --cached
git log -5 --oneline
gh auth status
git config --get commit.gpgsign
gh pr view --json number,url,state 2>/dev/null || true
```

Checks:

- **Branch:** If on `main` with PR-bound changes, create a feature branch first
  (e.g. `feat/...`, `fix/...`).
- **Signing:** `commit.gpgsign` must be `true` (GPG or SSH). `-s` adds DCO
  signoff only; cryptographic signing is separate.
- **Secrets:** Scan diff for `.env`, keys, tokens. **Abort** if found.
- **PR:** Reuse an open PR on the current branch when one exists.

### Staging

Stage all **intentional** uncommitted changes. See exclude list in
[reference.md](reference.md). Never stage `LICENSE` or `LICENSES/**`.

If nothing remains to commit after exclusions, stop with a clear message.

---

## 2. Local validation (before commit)

Many checks require generated companion files committed alongside source
changes. See CONTRIBUTING "Adding or updating configuration keys".

Read and follow the verilyze **pre-merge-check** skill.

### 2.1 Classify paths

From session edits, `git diff`, `git diff --cached`, and unpushed commits:

1. **Production paths:** `**/*.rs`, `scripts/**/*.py`, `tests/scripts/**`.
2. **Language scope:** Python-only, Rust-only, Mixed, or Neither (skip coverage).
3. **New Rust files:** `git diff --diff-filter=A --name-only origin/main...HEAD -- '*.rs'`
   (include staged adds before first commit; see [reference.md](reference.md)).
4. **`targets.md` rows** for non-coverage gates.

### 2.2 Path-to-target matrix (exit 0 each)

| If diff touches | Run |
|-----------------|-----|
| `scripts/**/*.py`, `tests/scripts/**` | `make lint-python test-scripts` |
| `**/*.rs` | `make fmt-check clippy`, `make cargo-test` (or scoped crate) |
| `scripts/**/*.sh` | `make lint-shell` |
| Other targets.md rows | Same as in-repo matrix |
| **Python-only production** | `make coverage-quick-python` |
| **Rust-only production** | `make coverage-quick-rust` |
| **Mixed production** | `make coverage-quick` |
| **Any new `*.rs` added** | `make coverage-new-rust-check` |

Production logic changes: strict TDD per AGENTS.md.

### 2.3 Coverage thresholds

**Project (CI parity):** Rust aggregate line >= 85%, function >= 80%, region >=
85%; Python aggregate and each module line >= 95%.

**Ship-pr stricter (new `.rs` only):** line >= 95%, function >= 90%, region >=
95%.

### 2.4 Companion sync

Proactively regenerate companions when source paths changed (table in
[reference.md](reference.md)).

When the diff touches `Cargo.toml`, `Cargo.lock`, or `pyproject.toml`, run
`make check-sbom` (and `make check-third-party-licenses` or
`make check-pylock-dev` as applicable) **before** `make check-fast`.
`check-fast` does not run `check-sbom`; skipping this step can merge a stale
SBOM that fails full CI `make check`.

When workflow files change `github/codeql-action/upload-sarif` pins, run
`make sync-upload-sarif-example` and stage `examples/github-action-vlz-scan.yml`.

### 2.5 Reactive sync loop

Repeat until `check-fast` passes (max **5** iterations). Run suggested
generators when stderr says "out of sync" / "Run: make ...".

### 2.6 Final fast gate

**`make check-fast` must exit 0** before commit.

### 2.7 Optional CI parity

Before first push on large or risky PRs, consider `make -j check`.

### 2.8 Local failure classification

On local gate failure: fix and re-run (`change defect` by default). After a
clear systemic signal, follow [ci-learning.md](ci-learning.md) (in-repo
**Local failure path**). Do not post the CI failure-record PR comment for
local-only findings.

---

## 3. Commit (signed + DCO)

Draft message per CONTRIBUTING: Conventional Commits; subject <= 50 characters;
body wrapped at 72 characters.

```bash
git commit -s -m "$(cat <<'EOF'
<type>(<scope>): <subject>

<body if non-trivial>

EOF
)"
```

### Pre-commit hook retry loop

Repeat commit until pre-commit exits cleanly. Prefer a **new commit** after fmt
retry unless [commit-policy.md](commit-policy.md) single-commit mode applies.

---

## 4. Super-linter (after commit, before push)

```bash
make super-linter
```

Must exit 0 every time before push. Expect ~3-10 min.

---

## 5. Push and open PR

```bash
SHIP_PR_SH="$(git rev-parse --show-toplevel)/.cursor/skills/verilyze-ship-pr/scripts/ship-pr.sh"
"${SHIP_PR_SH}" push
```

Create PR only when none exists. Write the body (with managed marker) to a
temp file, then:

```bash
"${SHIP_PR_SH}" create-pr --title "<subject>" --body-file /tmp/ship-pr-body.md
```

Do **not** put `git push` or `gh pr create` in the Shell command string.
Body template: [reference.md](reference.md).

---

## 6. Monitor CI and fix loop

```bash
gh pr checks --watch
gh pr view --json statusCheckRollup,mergeable,mergeStateStatus
```

On failure:

1. Launch **ci-investigator** on the failed job.
2. Post structured evidence per [ci-learning.md](ci-learning.md).
3. Fix scoped issues; follow [commit-policy.md](commit-policy.md) for commits.
4. Re-run validation (section 2), commit, super-linter, push.
5. Max **3** fix-and-push cycles.

### Sync with main (when BEHIND)

```bash
git fetch origin
git rebase origin/main
"${SHIP_PR_SH}" force-push
```

Resolve conflicts preserving intent; abort and ask the user if intents clash.

---

## 7. Merge (merge commit, admin bypass)

When required checks pass:

```bash
"${SHIP_PR_SH}" merge
```

Do **not** put `gh pr merge --admin` in the Shell command string.

Do not declare success until `state == "MERGED"`.

---

## 8. Post-merge sync

```bash
git checkout main && git pull --prune
```

Optionally delete the local feature branch.
