# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Native super-linter parity gate (subprocess smoke test)."""

import subprocess

from tests.scripts.repo_root import repo_root


def test_check_super_linter_native_make_target_passes() -> None:
    root = repo_root()
    subprocess.run(
        ["make", "-f", str(root / "Makefile"), "check-super-linter-native"],
        check=True,
        cwd=root,
    )
