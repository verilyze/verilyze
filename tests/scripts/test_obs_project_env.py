# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS obs-project.env parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.obs_project_env import (
    ObsProjectEnv,
    parse_obs_project_env,
    validate_obs_project_env_key_order,
)


def test_parse_obs_project_env_loads_all_keys(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "# comment",
                "OBS_PROJECT=home:example:proj",
                "OBS_PACKAGE=example-pkg",
                "OBS_SPEC_FILENAME=example.spec",
                "OBS_CHANGES_FILENAME=example.changes",
                "OBS_LEGACY_CHANGES_FILENAME=example.spec.changes",
                "OBS_MAINTAINER=Example <example@example.com>",
            ]
        ),
        encoding="utf-8",
    )

    env = parse_obs_project_env(env_file)

    assert env == ObsProjectEnv(
        obs_project="home:example:proj",
        obs_package="example-pkg",
        obs_spec_filename="example.spec",
        obs_changes_filename="example.changes",
        obs_legacy_changes_filename="example.spec.changes",
        obs_maintainer="Example <example@example.com>",
    )


def test_parse_obs_project_env_uses_defaults_for_optional_keys(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "OBS_PROJECT=home:test\nOBS_PACKAGE=test\n",
        encoding="utf-8",
    )

    env = parse_obs_project_env(env_file)

    assert env.obs_spec_filename == "verilyze.spec"
    assert env.obs_changes_filename == "verilyze.changes"
    assert env.obs_legacy_changes_filename == "verilyze.spec.changes"
    assert env.obs_maintainer == "Travis Post <post.travis@gmail.com>"


def test_parse_obs_project_env_raises_when_file_missing(tmp_path: Path) -> None:
    missing = tmp_path / "missing.env"
    with pytest.raises(FileNotFoundError, match="OBS config file not found"):
        parse_obs_project_env(missing)


def test_parse_obs_project_env_raises_when_required_keys_missing(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text("OBS_PROJECT=home:test\n", encoding="utf-8")

    with pytest.raises(ValueError, match="OBS_PACKAGE"):
        parse_obs_project_env(env_file)


def test_parse_obs_project_env_strips_quoted_values(tmp_path: Path) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "OBS_PROJECT=home:test",
                'OBS_PACKAGE=test',
                'OBS_MAINTAINER="Quoted Maintainer <quoted@example.com>"',
            ]
        ),
        encoding="utf-8",
    )

    env = parse_obs_project_env(env_file)
    assert env.obs_maintainer == "Quoted Maintainer <quoted@example.com>"


def test_parse_obs_project_env_skips_blank_and_comment_lines(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "",
                "# header",
                " =ignored",
                "OBS_PROJECT=home:test",
                "OBS_PACKAGE=test",
            ]
        ),
        encoding="utf-8",
    )

    env = parse_obs_project_env(env_file)
    assert env.obs_project == "home:test"
    assert env.obs_package == "test"


def test_validate_obs_project_env_key_order_accepts_sorted_keys(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "\n".join(
            [
                "OBS_ALPHA=1",
                "OBS_BETA=2",
                "OBS_GAMMA=3",
            ]
        ),
        encoding="utf-8",
    )
    validate_obs_project_env_key_order(env_file)


def test_validate_obs_project_env_key_order_rejects_unsorted_keys(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "obs-project.env"
    env_file.write_text(
        "OBS_Z=1\nOBS_A=2\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="UnorderedKey"):
        validate_obs_project_env_key_order(env_file)
