<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# CI learning (delegate)

**Source of truth:** follow
[`.cursor/skills/pre-merge-check/ai-learnings.md`](../pre-merge-check/ai-learnings.md).

Post failure evidence and `ai-learnings` issues **only** via:

`./scripts/ai-learnings-gh-post.sh` (gitleaks preflight; sets type Learning;
no raw `gh` for these). After create, the wrapper verifies label
`ai-learnings` and type `Learning`; do not use Cursor GitHub integration
for issue intake.

Do not maintain a second copy of classification, create rules, promotion
order, or posting policy here.

**CI failure** in ship-pr: launch **ci-investigator**, then follow the in-repo
procedure (PR failure record + issues for systemic / `uncertain`).

**Local gate failure** in ship-pr validation: classify per in-repo policy.
Default `change defect` (fix and re-run). After a clear systemic signal,
follow the **Local failure path** in `ai-learnings.md` (issues via wrapper;
never the CI failure-record PR comment for local-only; no ci-investigator).
