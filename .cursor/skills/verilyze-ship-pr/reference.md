<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# verilyze-ship-pr reference

Quick lookup for agents running the ship-PR pipeline.

## Ship-pr script path

Define once per ship session (works from any directory inside the repository):

```bash
SHIP_PR_SH="$(git rev-parse --show-toplevel)/.cursor/skills/verilyze-ship-pr/scripts/ship-pr.sh"
```

Invoke remote writes only as `"${SHIP_PR_SH}" <mode>`. The script moves to the
repository root and refuses `push`, `force-push`, `merge`, and `create-pr` on
`main`.

## Single-PR checklist

```
- [ ] 1. Preflight (branch, signing, secrets, existing PR)
- [ ] 2. Stage intentional changes (exclude junk)
- [ ] 3. Classify paths (language scope, new .rs files, targets.md rows)
- [ ] 4. Path-specific targets (lint, tests, companions; include `check-sbom` when manifests change)
- [ ] 5. Scoped coverage (python / rust / full) exit 0
- [ ] 6. New .rs files: make coverage-new-rust-check (if any added)
- [ ] 7. make check-fast (exit 0)
- [ ] 8. git commit -s (+ hook retry until clean)
- [ ] 9. make super-linter (exit 0)
- [ ] 10. ${SHIP_PR_SH} push
- [ ] 11. ${SHIP_PR_SH} create-pr (or reuse open PR; include managed marker)
- [ ] 12. gh pr checks --watch (green)
- [ ] 13. ${SHIP_PR_SH} merge (state MERGED)
- [ ] 14. git checkout main && git pull --prune
```

## Split-queue checklist

```
- [ ] 1. Inventory all work vs origin/main
- [ ] 2. Propose slices; user approves
- [ ] 3. Backup ref + queue.json written
- [ ] 4. Materialize current slice on main
- [ ] 5. Run single-PR pipeline for slice
- [ ] 6. Merge slice; sync main
- [ ] 7. Advance current_slice_index
- [ ] 8. Repeat until all slices merged or queue stopped
- [ ] 9. Cleanup only on user request
```

See [split-queue.md](split-queue.md) for manifest format and resume rules.

## Path classification

**Inputs:** session edits, `git diff`, `git diff --cached`, unpushed commits.

| Scope | Condition | Coverage command |
|-------|-----------|------------------|
| Python-only | `scripts/**/*.py` or `tests/scripts/**`; no `.rs` | `make coverage-quick-python` |
| Rust-only | `**/*.rs`; no Python production paths | `make coverage-quick-rust` |
| Mixed | Both Rust and Python production paths | `make coverage-quick` |
| Neither | Docs, workflows, packaging only | Skip coverage |

**New Rust files** (`git diff --diff-filter=A`):

```bash
git fetch origin main 2>/dev/null || true
git diff --diff-filter=A --name-only origin/main...HEAD -- '*.rs'
git diff --cached --diff-filter=A --name-only -- '*.rs'
```

When any new `.rs` paths exist:

```bash
make coverage-new-rust-check
```

## Coverage thresholds

**Project (CI):** Rust aggregate line >= 85%, function >= 80%, region >= 85%;
Python aggregate and each `scripts/*.py` module line >= 95%.

**Ship-pr (new `.rs` only):** line >= 95%, function >= 90%, region >= 95%.

Debug Python gaps:

```bash
VLZ_COVERAGE_VERBOSE=1 make coverage-quick-python
```

## Path-to-target matrix

| If diff touches | Run (exit 0) |
|-----------------|--------------|
| `scripts/**/*.py`, `tests/scripts/**` | `make lint-python test-scripts` |
| `**/*.rs` | `make fmt-check clippy`, `make cargo-test` |
| `scripts/**/*.sh` | `make lint-shell` |
| `architecture/**/*.mmd` | `make check-doc-diagrams` |
| config / `verilyze.conf.example` | `make check-config-docs` |
| `man/**` | `make check-manpages` |
| `packaging/**` | `make check-packaging` |
| `Cargo.toml`, `Cargo.lock`, `deny.toml` | `make cargo-check-locked`, `make deny-check`, `make check-third-party-licenses`, `make check-sbom` |
| `pyproject.toml` | `make check-sbom`, `make check-pylock-dev` |
| `.github/workflows/*.yml` (upload-sarif) | `make sync-upload-sarif-example`, `make check-upload-sarif-example` |
| New source files | `make check-headers` |
| Super-linter paths | `make super-linter` (also before every push) |

See in-repo [targets.md](.cursor/skills/pre-merge-check/targets.md).

## Optional CI parity

```bash
make -j check
```

## Staging excludes

Never stage: `LICENSE`, `LICENSES/**`, `__pycache__/`, `*.pyc`, `.venv-*`,
`target/`, editor cruft. Do not blanket `git add -A`.

## Companion file generators

| If you changed | Run | Stage these outputs |
|---|---|---|
| Config keys | `make generate-config-example` | `verilyze.conf.example`, `docs/configuration.md`, `man/verilyze.conf.5` |
| CLI | `make generate-manpages` | `man/vlz.1` |
| CLI completions | `make generate-completions` | `completions/*` |
| `architecture/**/*.mmd` | `make update-doc-diagrams` | `README.md`, `CONTRIBUTING.md` |
| `Cargo.toml`, `Cargo.lock` | `make generate-third-party-licenses`, `make generate-sbom` | `THIRD-PARTY-LICENSES`, `sbom/**` |
| `pyproject.toml` | `make generate-pylock-dev`, `make generate-sbom` | `pylock.dev.toml`, `sbom/**` |
| `.github/workflows/*.yml` (upload-sarif) | `make sync-upload-sarif-example` | `examples/github-action-vlz-scan.yml` |
| New source files | `make headers` | files with SPDX blocks |
| Packaging / version | `make generate-packaging` | `packaging/**` |

Companion-sync loop cap: **5** iterations. CI fix loop cap: **3** push cycles.

## Super-linter

```bash
make super-linter
```

Docker via `scripts/super-linter.sh`. Not `check-super-linter-native` alone.

## gh commands

### Preflight PR detection

```bash
gh pr view --json number,url,state 2>/dev/null || true
```

### Create PR (with managed marker)

Write the body to a file (include the managed marker), then call the allowlisted
script. Do **not** inline `gh pr create`.

```bash
cat > /tmp/ship-pr-body.md <<'EOF'
<!-- verilyze-ship-pr:managed -->

## Summary
- ...

## Test plan
- [ ] Local: path-specific targets from targets.md
- [ ] Local: scoped coverage per diff
- [ ] Local: make check-fast
- [ ] Local: make super-linter
- [ ] CI green

EOF
${SHIP_PR_SH} create-pr --title "<subject>" --body-file /tmp/ship-pr-body.md
```

### Monitor checks

```bash
gh pr checks --watch
gh pr view --json statusCheckRollup,mergeable,mergeStateStatus
```

### Failed run

```bash
gh run list --branch "$(git branch --show-current)" --limit 3
gh run view <run-id> --log-failed
gh run download <run-id> -n super-linter-logs
```

### Merge and confirm

```bash
${SHIP_PR_SH} merge
```

Do **not** inline `gh pr merge --admin`.

Required CI contexts: `check-dco`, `check-signatures`, `check`, `super-linter`.

### Sync behind main (rebase, not merge)

```bash
git fetch origin
git rebase origin/main
${SHIP_PR_SH} force-push
```

With explicit lease after amend:

```bash
${SHIP_PR_SH} force-push origin/<branch>:<known-remote-sha>
```

Do **not** inline `git push` or `git push --force-with-lease`.

## Queue manifest location

```
.git/verilyze-ship-pr/queue.json
```

See [split-queue.md](split-queue.md) for schema and status values.

## Escalation template

```markdown
## Ship PR stopped

**PR:** <url>
**Branch:** <branch>
**Last commit:** <sha> <subject>
**Queue slice:** <id or N/A>

**Failed check(s):** <names>
**Classification:** <from ci-learning.md>
**ci-investigator summary:** <one paragraph>

**Attempted fixes:** <bullets>
**CI-gap issue:** <url or none>
**Next steps for human:** <bullets>
```

## Related reference files

| File | Contents |
|------|----------|
| [single-pr.md](single-pr.md) | Full single-PR steps |
| [split-queue.md](split-queue.md) | Sequential split queue |
| [ci-learning.md](ci-learning.md) | CI + local systemic failure evidence (delegates) |
| [commit-policy.md](commit-policy.md) | Commit history policy |
| [dry-run.md](dry-run.md) | Verification scenarios |
