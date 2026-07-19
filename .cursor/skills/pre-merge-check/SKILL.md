---
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

name: pre-merge-check
description: Runs verilyze pre-merge and CI validation. Use after code edits, before commit or push, when CI fails, or when the user asks if changes are ready to merge.
---

# Pre-merge check

Do **not** invoke during Plan or Ask mode, or when no files were edited this
session. See [agent-workflow.mdc](../../rules/agent-workflow.mdc).

## Workflow

1. Confirm files were edited this session (or user explicitly requested checks)
2. Classify paths from session edits and git diff (`origin/main...HEAD`)
3. Run the **minimal** target set from [targets.md](targets.md) (not blind `make check`)
4. On failure, fix and re-run only the failed gate
5. Production behavior changed: `make check-pr` (Rust: 85% line/region, 80%
   function; scripts: 95% line aggregate and per module via `coverage-quick`)
6. Non-behavior changes before push/PR: `make check-fast` (must exit 0)
7. Remind human-only steps: signed commits, DCO, `git push`

Run `make check-pr` when the user asks to commit, push, open a PR, or assess
merge readiness on production logic changes. Do not auto-run it from the stop
hook.

## Super-linter

When diff touches super-linter paths (see [targets.md](targets.md)):

- **Must** run `make super-linter` (Docker) and confirm exit 0 before declaring done
- Optional: launch a **shell** subagent with `make super-linter` in background while running other gates
- After Renovate digest bumps or nightly badge failures: `make super-linter-full`

`make check-fast` includes `check-super-linter-native` (ENV key order and Checkov skip parity without Docker).

Skip local super-linter for Rust-only PRs; CI still runs incremental super-linter.

## Clippy

When `.rs` files changed:

- Single crate: `cargo clippy -p <crate> --all-targets -- -D warnings`
- Cross-crate: `make clippy`
- Before PR: rely on `make check-pr` for production behavior; `make check-fast`
  for non-behavior changes

## CI failure on existing PR

Use **ci-investigator** on the failed job. For super-linter: download `super-linter-logs` via `gh run download`.

## After checks pass

User may invoke Bugbot review, a security review subagent, or ask to babysit a PR (triage comments, fix CI).
Do not reference machine-local skill paths.
