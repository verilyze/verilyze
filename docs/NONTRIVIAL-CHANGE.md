<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Nontrivial Change Definition

This document defines what constitutes a *nontrivial* (legally significant) change for
copyright and attribution purposes in super-duper. It follows the [GNU Software
Maintenance Guidelines](https://www.gnu.org/prep/maintain/html_node/Legally-Significant.html).

## Threshold

A contribution is **nontrivial** if it constitutes **approximately 15 or more lines** of
original code or text. Changes below this threshold are not legally significant for
copyright purposes. The threshold is configured in `pyproject.toml` under
`[tool.spd-headers]`.

- **Cumulative:** A series of minor changes by the same person can add up. What matters
  is the total contribution per author per file, not each individual commit.
- **Additions:** Count lines added (additions), not deletions. Renames and mechanical
  edits that do not add substantial new content may be excluded.
- **Per file:** The threshold applies per file (or per logically distinct portion).
  Contributions across multiple files are evaluated separately for each file.

## What Does Not Count

The following do **not** count as nontrivial contributions for copyright purposes:

- **Ideas only** -- Suggestions, design input, or concepts without accompanying code
  or text. (These may deserve credit in an "Ideas by:" section but are not
  copyrightable contributions.)
- **Bug reports** -- Describing a problem without providing a fix.
- **Mechanical renames** -- e.g. renaming a symbol across many locations. Such
  changes are repetitive and do not represent substantial new authorship.

## Application

The `scripts/update_headers.py` automation uses this definition to determine which
contributors receive `SPDX-FileCopyrightText` attribution in each file. Only authors
who have contributed at least 15 lines to a file (cumulatively) are included in
that file's copyright notice.

## Reference

> A change of just a few lines (less than 15 or so) is not legally significant for
> copyright. A regular series of repeated changes, such as renaming a symbol, is not
> legally significant even if the symbol has to be renamed in many places. Keep in
> mind, however, that a series of minor changes by the same person can add up to a
> significant contribution.
>
> -- [GNU: Legally Significant Changes](https://www.gnu.org/prep/maintain/html_node/Legally-Significant.html)
