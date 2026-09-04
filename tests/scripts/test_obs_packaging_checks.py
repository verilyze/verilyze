# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""OBS packaging validation via check-obs-packaging.sh (NFR-021)."""

import os
import subprocess
from pathlib import Path

from tests.scripts.obs_signing_fixture import obs_signing_env
from tests.scripts.repo_root import repo_root


def test_check_obs_packaging_passes() -> None:
    """check-obs-packaging.sh validates OBS wiring and packaging invariants."""
    root = repo_root()
    env = os.environ.copy()
    env.update(obs_signing_env())
    subprocess.run(
        ["make", "-f", str(root / "Makefile"), "check-obs-packaging"],
        check=True,
        cwd=root,
        env=env,
    )


def test_check_obs_packaging_survives_repeated_pipefail_greps() -> None:
    """Regression: publish-obs block checks must not SIGPIPE under pipefail.

    CI failed when ``printf | grep -q`` closed early (Broken pipe) and the
    gate falsely reported missing ``--check``. Exercise the gate repeatedly.
    """
    root = repo_root()
    env = os.environ.copy()
    env.update(obs_signing_env())
    for _ in range(20):
        subprocess.run(
            ["make", "-f", str(root / "Makefile"), "check-obs-packaging"],
            check=True,
            cwd=root,
            env=env,
        )


def test_obs_project_env_assignment_keys_are_sorted() -> None:
    from scripts.obs_project_env import validate_obs_project_env_key_order

    env_file = repo_root() / "packaging" / "obs" / "obs-project.env"
    validate_obs_project_env_key_order(env_file)
