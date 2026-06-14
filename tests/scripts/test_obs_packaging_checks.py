# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for OBS packaging consistency wiring."""

import re

from pathlib import Path

from tests.scripts.workspace_helpers import top_obs_changes_version, workspace_semver


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_makefile_exposes_check_obs_packaging_target() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert ".PHONY: check-obs-packaging" in text
    assert "check-obs-packaging:" in text


def test_makefile_check_depends_on_obs_packaging_validation() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "check-obs-packaging" in text


def test_obs_project_env_has_required_coordinate_keys() -> None:
    env_file = _repo_root() / "packaging" / "obs" / "obs-project.env"
    text = env_file.read_text(encoding="utf-8")
    assert "OBS_PROJECT=" in text
    assert "OBS_PACKAGE=" in text
    assert "OBS_SPEC_FILENAME=verilyze.spec" in text
    assert "OBS_CHANGES_FILENAME=verilyze.changes" in text
    assert "OBS_LEGACY_CHANGES_FILENAME=verilyze.spec.changes" in text
    assert "OBS_MAINTAINER=" in text
    assert "OBS_WAIT_REPOSITORIES=" not in text
    assert "OBS_WAIT_TIMEOUT_SECONDS=" in text
    assert "OBS_WAIT_POLL_INTERVAL_SECONDS=" in text


def test_obs_project_meta_exists() -> None:
    project_meta = _repo_root() / "packaging" / "obs" / "project" / "_meta"
    assert project_meta.is_file()


def test_obs_enabled_build_repositories_non_empty() -> None:
    from tests.scripts.workspace_helpers import obs_enabled_build_repositories

    repos = obs_enabled_build_repositories()
    assert repos
    assert "openSUSE_Tumbleweed" in repos


def test_obs_project_env_assignment_keys_are_sorted() -> None:
    from scripts.obs_project_env import validate_obs_project_env_key_order

    env_file = _repo_root() / "packaging" / "obs" / "obs-project.env"
    validate_obs_project_env_key_order(env_file)


def test_makefile_exposes_check_super_linter_native_target() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "check-super-linter-native:" in text
    check_fast_block = text.split("check-fast:", maxsplit=1)[1].split(
        "check-slow:", maxsplit=1
    )[0]
    assert "check-super-linter-native" in check_fast_block


def test_obs_packaging_check_script_invokes_signing_check() -> None:
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "check-obs-signing.sh" in text


def test_obs_packaging_check_does_not_require_ripgrep() -> None:
    """GitHub Actions ubuntu-latest images do not install ripgrep by default."""
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "rg " not in text


def test_obs_spec_uses_literal_version_for_set_version_service() -> None:
    """Ensure OBS set_version can rewrite the spec Version field."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "%{!?version:%global version" not in spec_text
    assert re.search(r"^Version:\s+\d+\.\d+\.\d+$", spec_text, re.MULTILINE)


def test_obs_scm_strips_git_tag_v_prefix() -> None:
    """SemVer tags use leading v; rewrite keeps tarball/Source0 sane for RPM."""
    service_text = (
        _repo_root() / "packaging" / "obs" / "_service"
    ).read_text(encoding="utf-8")
    assert '<param name="versionrewrite-pattern">v(.*)</param>' in service_text
    assert '<param name="versionrewrite-replacement">\\1</param>' in service_text


def test_obs_upload_script_exists() -> None:
    """Release automation must ship sources via obs-upload-release-sources.sh."""
    upload_script = _repo_root() / "scripts" / "obs-upload-release-sources.sh"
    assert upload_script.is_file()
    assert upload_script.stat().st_mode & 0o111


def test_obs_changes_renderer_exists() -> None:
    render_script = _repo_root() / "scripts" / "render_obs_changes.py"
    assert render_script.is_file()
    assert render_script.stat().st_mode & 0o111


def test_obs_seed_changes_file_exists() -> None:
    changes_file = _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.changes"
    assert changes_file.is_file()
    assert top_obs_changes_version(changes_file.read_text(encoding="utf-8")) == (
        workspace_semver()
    )


def test_obs_spec_uses_offline_cargo_with_vendor_sources() -> None:
    """RPM spec must consume vendor archive and build offline."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "Source1:        vendor.tar.zst" in spec_text
    assert "Source2:        verilyze-rpmlintrc" in spec_text
    assert "cargo_config" not in spec_text
    assert "BuildRequires:  zstd" in spec_text
    assert "cargo build --release --locked --offline" in spec_text
    assert "tar --zstd -xf %{SOURCE1}" in spec_text


def test_debian_rules_uses_offline_cargo_with_vendor_sources() -> None:
    """Debian rules must extract vendor archive and build offline."""
    rules_text = (
        _repo_root()
        / "packaging"
        / "obs"
        / "debian"
        / "debian"
        / "rules"
    ).read_text(encoding="utf-8")
    assert "vendor.tar.zst" in rules_text
    assert "cargo_config" not in rules_text
    assert "cargo build --release --locked --offline" in rules_text


def test_debian_control_build_depends_includes_zstd() -> None:
    """Debian control must list zstd so vendor.tar.zst can be extracted."""
    control_text = (
        _repo_root()
        / "packaging"
        / "obs"
        / "debian"
        / "debian"
        / "control"
    ).read_text(encoding="utf-8")
    assert "zstd" in control_text


def test_obs_set_version_handles_optional_leading_v_in_basenames() -> None:
    """Upstream tags use v; OBS default set_version filename regex rejects those."""
    service_text = (
        _repo_root() / "packaging" / "obs" / "_service"
    ).read_text(encoding="utf-8")
    assert '<param name="basename">verilyze</param>' in service_text
    assert (
        '<param name="regex">^verilyze-v?(.*)\\.(?:tar\\.xz|obscpio|tar\\.gz|tar\\.zst)$</param>'
        in service_text
    )


def test_obs_packaging_check_asserts_upload_workflow_and_offline() -> None:
    """check-obs-packaging.sh must assert upload workflow and --offline."""
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "obs-upload-release-sources.sh" in text
    assert "render_obs_changes.py" in text
    assert "OBS_CHANGES_FILENAME" in text
    assert "remove_stale_source_archives" in text
    assert "obs_verify_vendor_lockfile" in text
    assert "obs_verify_package_checksums" in text
    assert "--skip-runservice" in text
    assert "vendor.tar.zst" in text
    assert "--offline" in text
    assert "obs-wait-for-builds.sh" in text
    assert "sync-obs-project-meta.sh" in text
    assert "--push" in text
    assert "OBS_WAIT_REPOSITORIES must not be set" in text


def test_obs_spec_keeps_empty_changelog_section() -> None:
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    changelog_start = spec_text.index("%changelog\n")
    assert spec_text[changelog_start:].strip() == "%changelog"


def test_obs_spec_lists_completion_parent_dirs_for_filelist_check() -> None:
    """openSUSE OBS brp filelist expects parent dirs owned when not from deps."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    for line in (
        "%dir %{_datadir}/zsh",
        "%dir %{_datadir}/zsh/site-functions",
        "%dir %{_datadir}/fish",
        "%dir %{_datadir}/fish/vendor_completions.d",
    ):
        assert line in spec_text


def test_obs_spec_declares_non_empty_check_section() -> None:
    """OBS RPM spec should include a meaningful %check section for rpmlint."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "\n%check\n" in spec_text
    assert 'set -- $(./target/release/%{crate_name} --version)' in spec_text
    assert 'actual_version="$2"' in spec_text
    assert 'expected_version="%{version}"' in spec_text
    assert '[ "$actual_version" = "$expected_version" ]' in spec_text
    assert "./target/release/%{crate_name} --help >/dev/null" in spec_text


def test_obs_spec_declares_suse_group_for_rpmlint() -> None:
    """Leap 15.7 rpmlint requires a valid legacy Group tag on SUSE targets."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "%if 0%{?suse_version}" in spec_text
    assert "Group:          Productivity/Security" in spec_text


def test_obs_spec_declares_rpmlintrc_source() -> None:
    """OBS rpmlint reads package-specific filters from Source2."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "Source2:        verilyze-rpmlintrc" in spec_text


def test_obs_rpmlintrc_filters_chroot_false_positive() -> None:
    rpmlintrc = _repo_root() / "packaging" / "obs" / "rpm" / "verilyze-rpmlintrc"
    assert rpmlintrc.is_file()
    text = rpmlintrc.read_text(encoding="utf-8")
    assert 'addFilter("missing-call-to-chdir-with-chroot")' in text


def test_obs_project_env_defines_rpmlintrc_filename() -> None:
    text = (_repo_root() / "packaging" / "obs" / "obs-project.env").read_text(
        encoding="utf-8"
    )
    assert "OBS_RPMLINTRC_FILENAME=verilyze-rpmlintrc" in text


def test_obs_packaging_check_asserts_upload_includes_rpmlintrc() -> None:
    check_text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    upload_text = (
        _repo_root() / "scripts" / "obs-upload-release-sources.sh"
    ).read_text(encoding="utf-8")
    assert "OBS_RPMLINTRC_FILENAME" in check_text
    assert "OBS_RPMLINTRC_FILENAME" in upload_text
