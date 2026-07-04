# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OBS repository derivation from committed _meta files."""

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.obs_repositories import (
    DEFAULT_PACKAGE_META_REL,
    DEFAULT_PROJECT_META_REL,
    enabled_build_repositories,
    format_repository_list,
    load_enabled_build_repositories,
    parse_package_disabled_repositories,
    parse_project_repository_names,
    validate_obs_meta_files,
)

_PROJECT_META = """\
<project name="home:example:proj">
  <title>example</title>
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Tumbleweed" repository="standard"/>
    <arch>x86_64</arch>
    <arch>aarch64</arch>
  </repository>
  <repository name="Fedora_44">
    <path project="Fedora:Rawhide" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
  <repository name="Fedora_43">
    <path project="Fedora:43" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
  <repository name="16.0">
    <path project="openSUSE:Leap:16.0" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
</project>
"""

_PROJECT_META_WITH_MAINTAINER = """\
<project name="home:example:proj">
  <title>example</title>
  <person userid="alice" role="maintainer"/>
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Tumbleweed" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
  <repository name="Fedora_43">
    <path project="Fedora:43" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
</project>
"""

_PROJECT_META_NO_MAINTAINER = """\
<project name="home:example:proj">
  <title>example</title>
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Tumbleweed" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
</project>
"""

_PACKAGE_META_NO_DISABLE = """\
<package name="verilyze" project="home:example:proj">
  <title>verilyze</title>
</package>
"""

_PACKAGE_META_WITH_DISABLE = """\
<package name="verilyze" project="home:example:proj">
  <title>verilyze</title>
  <build>
    <disable repository="Fedora_43"/>
  </build>
</package>
"""

_PACKAGE_META_INVALID_DISABLE = """\
<package name="verilyze" project="home:example:proj">
  <title>verilyze</title>
  <build>
    <disable repository="Fedora_42"/>
  </build>
</package>
"""

_EXPECTED_ALL_REPOS = (
    "16.0",
    "Fedora_43",
    "Fedora_44",
    "openSUSE_Tumbleweed",
)


def test_parse_project_repository_names_returns_sorted_unique_names() -> None:
    names = parse_project_repository_names(_PROJECT_META)
    assert names == _EXPECTED_ALL_REPOS


def test_parse_package_disabled_repositories_empty_when_no_build_flags() -> None:
    disabled = parse_package_disabled_repositories(_PACKAGE_META_NO_DISABLE)
    assert disabled == frozenset()


def test_parse_package_disabled_repositories_collects_repo_level_disables() -> None:
    disabled = parse_package_disabled_repositories(_PACKAGE_META_WITH_DISABLE)
    assert disabled == frozenset({"Fedora_43"})


def test_enabled_build_repositories_subtracts_disabled_repos() -> None:
    repos = enabled_build_repositories(_PROJECT_META, _PACKAGE_META_WITH_DISABLE)
    assert repos == (
        "16.0",
        "Fedora_44",
        "openSUSE_Tumbleweed",
    )


def test_enabled_build_repositories_returns_all_when_none_disabled() -> None:
    repos = enabled_build_repositories(_PROJECT_META, _PACKAGE_META_NO_DISABLE)
    assert repos == _EXPECTED_ALL_REPOS


def test_parse_project_repository_names_raises_when_no_repositories() -> None:
    empty_meta = '<project name="home:empty"><title>empty</title></project>'
    with pytest.raises(ValueError, match="no repository definitions"):
        parse_project_repository_names(empty_meta)


def test_format_repository_list_joins_with_commas() -> None:
    assert format_repository_list(("a", "b")) == "a,b"


def test_validate_obs_meta_files_accepts_valid_meta() -> None:
    validate_obs_meta_files(_PROJECT_META_WITH_MAINTAINER, _PACKAGE_META_WITH_DISABLE)


def test_validate_obs_meta_files_accepts_package_without_maintainers() -> None:
    validate_obs_meta_files(_PROJECT_META_WITH_MAINTAINER, _PACKAGE_META_NO_DISABLE)


def test_validate_obs_meta_files_raises_when_project_meta_malformed() -> None:
    with pytest.raises(ValueError, match="project _meta XML"):
        validate_obs_meta_files("<project>", _PACKAGE_META_NO_DISABLE)


def test_validate_obs_meta_files_raises_when_package_meta_malformed() -> None:
    with pytest.raises(ValueError, match="package _meta XML"):
        validate_obs_meta_files(_PROJECT_META_WITH_MAINTAINER, "<package>")


def test_validate_obs_meta_files_raises_when_no_project_maintainer() -> None:
    with pytest.raises(ValueError, match="maintainer"):
        validate_obs_meta_files(_PROJECT_META_NO_MAINTAINER, _PACKAGE_META_NO_DISABLE)


def test_validate_obs_meta_files_raises_when_disable_unknown_repository() -> None:
    with pytest.raises(ValueError, match="Fedora_42"):
        validate_obs_meta_files(
            _PROJECT_META_WITH_MAINTAINER,
            _PACKAGE_META_INVALID_DISABLE,
        )


def test_validate_obs_meta_files_raises_when_project_has_no_repositories() -> None:
    no_repos_meta = """\
<project name="home:empty">
  <title>empty</title>
  <person userid="alice" role="maintainer"/>
</project>
"""
    with pytest.raises(ValueError, match="repository definitions"):
        validate_obs_meta_files(no_repos_meta, _PACKAGE_META_NO_DISABLE)


def test_load_enabled_build_repositories_reads_committed_files(
    tmp_path: Path,
) -> None:
    project_meta = tmp_path / "project" / "_meta"
    package_meta = tmp_path / "rpm" / "_meta"
    project_meta.parent.mkdir(parents=True)
    package_meta.parent.mkdir(parents=True)
    project_meta.write_text(_PROJECT_META, encoding="utf-8")
    package_meta.write_text(_PACKAGE_META_NO_DISABLE, encoding="utf-8")

    repos = load_enabled_build_repositories(
        tmp_path,
        project_meta_path=project_meta,
        package_meta_path=package_meta,
    )
    assert repos == _EXPECTED_ALL_REPOS


def test_load_enabled_build_repositories_raises_when_project_meta_missing(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError, match="project _meta"):
        load_enabled_build_repositories(
            tmp_path,
            project_meta_path=tmp_path / "missing" / "_meta",
            package_meta_path=tmp_path / "rpm" / "_meta",
        )


def test_default_meta_paths_match_packaging_layout() -> None:
    assert DEFAULT_PROJECT_META_REL == Path("packaging/obs/project/_meta")
    assert DEFAULT_PACKAGE_META_REL == Path("packaging/obs/rpm/_meta")


def test_load_enabled_build_repositories_raises_when_package_meta_missing(
    tmp_path: Path,
) -> None:
    project_meta = tmp_path / "project" / "_meta"
    project_meta.parent.mkdir(parents=True)
    project_meta.write_text(_PROJECT_META, encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="package _meta"):
        load_enabled_build_repositories(
            tmp_path,
            project_meta_path=project_meta,
            package_meta_path=tmp_path / "missing" / "_meta",
        )


def test_main_cli_prints_repository_list(tmp_path: Path) -> None:
    from scripts.obs_repositories import main

    project_meta = tmp_path / "project" / "_meta"
    package_meta = tmp_path / "rpm" / "_meta"
    project_meta.parent.mkdir(parents=True)
    package_meta.parent.mkdir(parents=True)
    project_meta.write_text(_PROJECT_META, encoding="utf-8")
    package_meta.write_text(_PACKAGE_META_NO_DISABLE, encoding="utf-8")

    import io
    import sys

    buf = io.StringIO()
    argv = [
        "obs_repositories.py",
        "--repo-root",
        str(tmp_path),
        "--project-meta",
        str(project_meta),
        "--package-meta",
        str(package_meta),
    ]
    with patch.object(sys, "argv", argv), patch.object(sys, "stdout", buf):
        assert main() == 0
    assert buf.getvalue().strip() == format_repository_list(_EXPECTED_ALL_REPOS)


def test_main_cli_validate_exits_zero_for_valid_meta(tmp_path: Path) -> None:
    import sys

    from scripts.obs_repositories import main

    project_meta = tmp_path / "project" / "_meta"
    package_meta = tmp_path / "rpm" / "_meta"
    project_meta.parent.mkdir(parents=True)
    package_meta.parent.mkdir(parents=True)
    project_meta.write_text(_PROJECT_META_WITH_MAINTAINER, encoding="utf-8")
    package_meta.write_text(_PACKAGE_META_WITH_DISABLE, encoding="utf-8")

    argv = [
        "obs_repositories.py",
        "--validate",
        "--repo-root",
        str(tmp_path),
        "--project-meta",
        str(project_meta),
        "--package-meta",
        str(package_meta),
    ]
    with patch.object(sys, "argv", argv):
        assert main() == 0
