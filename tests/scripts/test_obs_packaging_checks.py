# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""OBS packaging validation via check-obs-packaging.sh (NFR-021)."""

import os
import subprocess
from pathlib import Path

from tests.scripts.obs_signing_fixture import obs_signing_env


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_check_obs_packaging_passes() -> None:
    """check-obs-packaging.sh validates OBS wiring and packaging invariants."""
    root = _repo_root()
    env = os.environ.copy()
    env.update(obs_signing_env())
    subprocess.run(
        ["make", "-f", str(root / "Makefile"), "check-obs-packaging"],
        check=True,
        cwd=root,
        env=env,
    )


def test_obs_project_env_assignment_keys_are_sorted() -> None:
    from scripts.obs_project_env import validate_obs_project_env_key_order

    env_file = _repo_root() / "packaging" / "obs" / "obs-project.env"
    validate_obs_project_env_key_order(env_file)
