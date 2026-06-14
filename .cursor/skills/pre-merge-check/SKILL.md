---
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

name: pre-merge-check
description: Runs verilyze pre-merge and CI validation. Use when finishing a task, before commit or push, when CI fails, or when the user asks if changes are ready to merge.
---

# Pre-merge check

## Workflow

1. Classify paths from working tree, index, and unpushed commits (`origin/main...HEAD`)
2. Run the **minimal** target set from [targets.md](targets.md) (not blind `make check`)
3. On failure, fix and re-run only the failed gate
4. Behavior changed: `make coverage-quick` (85% line/region, 80% function) but
   attempt to reach as close as reasonably possible to 100%
5. Before PR: `make check-fast` (must exit 0)
6. Remind human-only steps: signed commits, DCO, `git push`

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
- Before PR: rely on `make check-fast` unless only Rust gates are needed

## CI failure on existing PR

Use **ci-investigator** on the failed job. For super-linter: download `super-linter-logs` via `gh run download`.

## After checks pass

User may invoke Bugbot review, a security review subagent, or ask to babysit a PR (triage comments, fix CI).
Do not reference machine-local skill paths.
